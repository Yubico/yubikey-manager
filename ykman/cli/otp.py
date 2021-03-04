# Copyright (c) 2015 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from yubikit.yubiotp import (
    SLOT,
    YubiOtpSession,
    YubiOtpSlotConfiguration,
    HmacSha1SlotConfiguration,
    StaticPasswordSlotConfiguration,
    HotpSlotConfiguration,
    UpdateConfiguration,
)
from yubikit.core import TRANSPORT, CommandError
from yubikit.core.otp import modhex_encode, modhex_decode, OtpConnection

from .util import (
    ykman_group,
    cli_fail,
    click_force_option,
    click_callback,
    click_parse_b32_key,
    click_postpone_execution,
    click_prompt,
    prompt_for_touch,
    EnumChoice,
)
from .. import __version__
from ..device import is_fips_version
from ..scancodes import encode, KEYBOARD_LAYOUT
from ..otp import (
    PrepareUploadFailed,
    prepare_upload_key,
    is_in_fips_mode,
    generate_static_pw,
    parse_oath_key,
    parse_b32_key,
    time_challenge,
    format_oath_code,
)
from threading import Event
from time import time
import logging
import os
import struct
import click
import webbrowser


logger = logging.getLogger(__name__)


def parse_hex(length):
    @click_callback()
    def inner(ctx, param, val):
        val = bytes.fromhex(val)
        if len(val) != length:
            raise ValueError(f"Must be exactly {length} bytes.")
        return val

    return inner


def parse_access_code_hex(access_code_hex):
    try:
        access_code = bytes.fromhex(access_code_hex)
    except TypeError as e:
        raise ValueError(e)
    if len(access_code) != 6:
        raise ValueError("Must be exactly 6 bytes.")

    return access_code


click_slot_argument = click.argument(
    "slot", type=click.Choice(["1", "2"]), callback=lambda c, p, v: SLOT(int(v))
)


def _failed_to_write_msg(ctx, exc_info):
    logger.error("Failed to write to device", exc_info=exc_info)
    cli_fail(
        "Failed to write to the YubiKey. Make sure the device does not "
        "have restricted access."
    )


def _confirm_slot_overwrite(slot_state, slot):
    if slot_state.is_configured(slot):
        click.confirm(
            f"Slot {slot} is already configured. Overwrite configuration?",
            abort=True,
            err=True,
        )


@ykman_group(OtpConnection)
@click.pass_context
@click_postpone_execution
@click.option(
    "--access-code",
    required=False,
    metavar="HEX",
    help="A 6 byte access code. Set to empty to use a prompt for input.",
)
def otp(ctx, access_code):
    """
    Manage the YubiOTP application.

    The YubiKey provides two keyboard-based slots which can each be configured
    with a credential. Several credential types are supported.

    A slot configuration may be write-protected with an access code. This
    prevents the configuration to be overwritten without the access code
    provided. Mode switching the YubiKey is not possible when a slot is
    configured with an access code.

    Examples:

    \b
      Swap the configurations between the two slots:
      $ ykman otp swap

    \b
      Program a random challenge-response credential to slot 2:
      $ ykman otp chalresp --generate 2

    \b
      Program a Yubico OTP credential to slot 1, using the serial as public id:
      $ ykman otp yubiotp 1 --serial-public-id

    \b
      Program a random 38 characters long static password to slot 2:
      $ ykman otp static --generate 2 --length 38
    """

    ctx.obj["session"] = YubiOtpSession(ctx.obj["conn"])
    if access_code is not None:
        if access_code == "":
            access_code = click_prompt("Enter the access code", show_default=False)

        try:
            access_code = parse_access_code_hex(access_code)
        except Exception as e:
            ctx.fail("Failed to parse access code: " + str(e))

    ctx.obj["access_code"] = access_code


@otp.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the YubiKey OTP slots.
    """
    session = ctx.obj["session"]
    state = session.get_config_state()
    slot1 = state.is_configured(1)
    slot2 = state.is_configured(2)

    click.echo(f"Slot 1: {slot1 and 'programmed' or 'empty'}")
    click.echo(f"Slot 2: {slot2 and 'programmed' or 'empty'}")

    if is_fips_version(session.version):
        click.echo(f"FIPS Approved Mode: {'Yes' if is_in_fips_mode(session) else 'No'}")


@otp.command()
@click.confirmation_option("-f", "--force", prompt="Swap the two slots of the YubiKey?")
@click.pass_context
def swap(ctx):
    """
    Swaps the two slot configurations.
    """
    session = ctx.obj["session"]
    click.echo("Swapping slots...")
    try:
        session.swap_slots()
    except CommandError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.pass_context
@click.option("-p", "--prefix", help="Added before the NDEF payload. Typically a URI.")
def ndef(ctx, slot, prefix):
    """
    Configure a slot to be used over NDEF (NFC).

    The default prefix will be used if no prefix is specified:

        "https://my.yubico.com/yk/#"
    """
    info = ctx.obj["info"]
    session = ctx.obj["session"]
    state = session.get_config_state()
    if not info.has_transport(TRANSPORT.NFC):
        cli_fail("This YubiKey does not support NFC.")

    if not state.is_configured(slot):
        cli_fail(f"Slot {slot} is empty.")

    try:
        session.set_ndef_configuration(slot, prefix, ctx.obj["access_code"])
    except CommandError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click_force_option
@click.pass_context
def delete(ctx, slot, force):
    """
    Deletes the configuration stored in a slot.
    """
    session = ctx.obj["session"]
    state = session.get_config_state()
    if not force and not state.is_configured(slot):
        cli_fail("Not possible to delete an empty slot.")
    force or click.confirm(
        f"Do you really want to delete the configuration of slot {slot}?",
        abort=True,
        err=True,
    )
    click.echo(f"Deleting the configuration in slot {slot}...")
    try:
        session.delete_slot(slot, ctx.obj["access_code"])
    except CommandError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.option(
    "-P",
    "--public-id",
    required=False,
    help="Public identifier prefix.",
    metavar="MODHEX",
)
@click.option(
    "-p",
    "--private-id",
    required=False,
    metavar="HEX",
    callback=parse_hex(6),
    help="6 byte private identifier.",
)
@click.option(
    "-k",
    "--key",
    required=False,
    metavar="HEX",
    callback=parse_hex(16),
    help="16 byte secret key.",
)
@click.option(
    "--no-enter",
    is_flag=True,
    help="Don't send an Enter keystroke after emitting the OTP.",
)
@click.option(
    "-S",
    "--serial-public-id",
    is_flag=True,
    required=False,
    help="Use YubiKey serial number as public ID. Conflicts with --public-id.",
)
@click.option(
    "-g",
    "--generate-private-id",
    is_flag=True,
    required=False,
    help="Generate a random private ID. Conflicts with --private-id.",
)
@click.option(
    "-G",
    "--generate-key",
    is_flag=True,
    required=False,
    help="Generate a random secret key. Conflicts with --key.",
)
@click.option(
    "-u",
    "--upload",
    is_flag=True,
    required=False,
    help="Upload credential to YubiCloud (opens in browser). Conflicts with --force.",
)
@click_force_option
@click.pass_context
def yubiotp(
    ctx,
    slot,
    public_id,
    private_id,
    key,
    no_enter,
    force,
    serial_public_id,
    generate_private_id,
    generate_key,
    upload,
):
    """
    Program a Yubico OTP credential.
    """

    info = ctx.obj["info"]
    session = ctx.obj["session"]

    if public_id and serial_public_id:
        ctx.fail("Invalid options: --public-id conflicts with --serial-public-id.")

    if private_id and generate_private_id:
        ctx.fail("Invalid options: --private-id conflicts with --generate-public-id.")

    if upload and force:
        ctx.fail("Invalid options: --upload conflicts with --force.")

    if key and generate_key:
        ctx.fail("Invalid options: --key conflicts with --generate-key.")

    if not public_id:
        if serial_public_id:
            serial = session.get_serial()
            if serial is None:
                cli_fail("Serial number not set, public ID must be provided")
            public_id = modhex_encode(b"\xff\x00" + struct.pack(b">I", serial))
            click.echo(f"Using YubiKey serial as public ID: {public_id}")
        elif force:
            ctx.fail(
                "Public ID not given. Please remove the --force flag, or "
                "add the --serial-public-id flag or --public-id option."
            )
        else:
            public_id = click_prompt("Enter public ID")

    try:
        public_id = modhex_decode(public_id)
    except KeyError:
        ctx.fail("Invalid public ID, must be modhex.")

    if not private_id:
        if generate_private_id:
            private_id = os.urandom(6)
            click.echo(f"Using a randomly generated private ID: {private_id.hex()}")
        elif force:
            ctx.fail(
                "Private ID not given. Please remove the --force flag, or "
                "add the --generate-private-id flag or --private-id option."
            )
        else:
            private_id = click_prompt("Enter private ID")
            private_id = bytes.fromhex(private_id)

    if not key:
        if generate_key:
            key = os.urandom(16)
            click.echo(f"Using a randomly generated secret key: {key.hex()}")
        elif force:
            ctx.fail(
                "Secret key not given. Please remove the --force flag, or "
                "add the --generate-key flag or --key option."
            )
        else:
            key = click_prompt("Enter secret key")
            key = bytes.fromhex(key)

    if not upload and not force:
        upload = click.confirm("Upload credential to YubiCloud?", abort=False, err=True)
    if upload:
        try:
            upload_url = prepare_upload_key(
                key,
                public_id,
                private_id,
                serial=info.serial,
                user_agent="ykman/" + __version__,
            )
            click.echo("Upload to YubiCloud initiated successfully.")
        except PrepareUploadFailed as e:
            error_msg = "\n".join(e.messages())
            cli_fail("Upload to YubiCloud failed.\n" + error_msg)

    force or click.confirm(
        f"Program a YubiOTP credential in slot {slot}?", abort=True, err=True
    )

    try:
        session.put_configuration(
            slot,
            YubiOtpSlotConfiguration(public_id, private_id, key).append_cr(
                not no_enter
            ),
            ctx.obj["access_code"],
            ctx.obj["access_code"],
        )
    except CommandError as e:
        _failed_to_write_msg(ctx, e)

    if upload:
        click.echo("Opening upload form in browser: " + upload_url)
        webbrowser.open_new_tab(upload_url)


@otp.command()
@click_slot_argument
@click.argument("password", required=False)
@click.option("-g", "--generate", is_flag=True, help="Generate a random password.")
@click.option(
    "-l",
    "--length",
    metavar="LENGTH",
    type=click.IntRange(1, 38),
    default=38,
    show_default=True,
    help="Length of generated password.",
)
@click.option(
    "-k",
    "--keyboard-layout",
    type=EnumChoice(KEYBOARD_LAYOUT),
    default="MODHEX",
    show_default=True,
    help="Keyboard layout to use for the static password.",
)
@click.option(
    "--no-enter",
    is_flag=True,
    help="Don't send an Enter keystroke after outputting the password.",
)
@click_force_option
@click.pass_context
def static(ctx, slot, password, generate, length, keyboard_layout, no_enter, force):
    """
    Configure a static password.

    To avoid problems with different keyboard layouts, the following characters
    (upper and lower case) are allowed by default: cbdefghijklnrtuv

    Use the --keyboard-layout option to allow more characters based on
    preferred keyboard layout.
    """

    session = ctx.obj["session"]

    if password and len(password) > 38:
        ctx.fail("Password too long (maximum length is 38 characters).")
    if generate and not length:
        ctx.fail("Provide a length for the generated password.")

    if not password and not generate:
        password = click_prompt("Enter a static password")
    elif not password and generate:
        password = generate_static_pw(length, keyboard_layout)

    scan_codes = encode(password, keyboard_layout)

    if not force:
        _confirm_slot_overwrite(session.get_config_state(), slot)
    try:
        session.put_configuration(
            slot,
            StaticPasswordSlotConfiguration(scan_codes).append_cr(not no_enter),
            ctx.obj["access_code"],
            ctx.obj["access_code"],
        )
    except CommandError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.argument("key", required=False)
@click.option(
    "-t",
    "--touch",
    is_flag=True,
    help="Require touch on the YubiKey to generate a response.",
)
@click.option(
    "-T",
    "--totp",
    is_flag=True,
    required=False,
    help="Use a base32 encoded key for TOTP credentials.",
)
@click.option(
    "-g",
    "--generate",
    is_flag=True,
    required=False,
    help="Generate a random secret key. Conflicts with KEY argument.",
)
@click_force_option
@click.pass_context
def chalresp(ctx, slot, key, totp, touch, force, generate):
    """
    Program a challenge-response credential.

    If KEY is not given, an interactive prompt will ask for it.
    """
    session = ctx.obj["session"]

    if key:
        if generate:
            ctx.fail("Invalid options: --generate conflicts with KEY argument.")
        elif totp:
            key = parse_b32_key(key)
        else:
            key = parse_oath_key(key)
    else:
        if force and not generate:
            ctx.fail(
                "No secret key given. Please remove the --force flag, "
                "set the KEY argument or set the --generate flag."
            )
        elif totp:
            while True:
                key = click_prompt("Enter a secret key (base32)")
                try:
                    key = parse_b32_key(key)
                    break
                except Exception as e:
                    click.echo(e)
        else:
            if generate:
                key = os.urandom(20)
                click.echo(f"Using a randomly generated key: {key.hex()}")
            else:
                key = click_prompt("Enter a secret key")
                key = parse_oath_key(key)

    cred_type = "TOTP" if totp else "challenge-response"
    force or click.confirm(
        f"Program a {cred_type} credential in slot {slot}?", abort=True, err=True,
    )
    try:
        session.put_configuration(
            slot,
            HmacSha1SlotConfiguration(key).require_touch(touch),
            ctx.obj["access_code"],
            ctx.obj["access_code"],
        )
    except CommandError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.argument("challenge", required=False)
@click.option(
    "-T",
    "--totp",
    is_flag=True,
    help="Generate a TOTP code, use the current time if challenge is omitted.",
)
@click.option(
    "-d",
    "--digits",
    type=click.Choice(["6", "8"]),
    default="6",
    help="Number of digits in generated TOTP code (default: 6).",
)
@click.pass_context
def calculate(ctx, slot, challenge, totp, digits):
    """
    Perform a challenge-response operation.

    Send a challenge (in hex) to a YubiKey slot with a challenge-response
    credential, and read the response. Supports output as a OATH-TOTP code.
    """
    session = ctx.obj["session"]

    if not challenge and not totp:
        challenge = click_prompt("Enter a challenge (hex)")

    # Check that slot is not empty
    if not session.get_config_state().is_configured(slot):
        cli_fail("Cannot perform challenge-response on an empty slot.")

    if totp:  # Challenge omitted or timestamp
        if challenge is None:
            challenge = time_challenge(time())
        else:
            try:
                challenge = time_challenge(int(challenge))
            except Exception as e:
                logger.error("Error", exc_info=e)
                ctx.fail("Timestamp challenge for TOTP must be an integer.")
    else:  # Challenge is hex
        challenge = bytes.fromhex(challenge)

    try:
        event = Event()

        def on_keepalive(status):
            if not hasattr(on_keepalive, "prompted") and status == 2:
                prompt_for_touch()
                on_keepalive.prompted = True

        response = session.calculate_hmac_sha1(slot, challenge, event, on_keepalive)
        if totp:
            value = format_oath_code(response, int(digits))
        else:
            value = response.hex()

        click.echo(value)
    except CommandError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.argument("key", callback=click_parse_b32_key, required=False)
@click.option(
    "-d",
    "--digits",
    type=click.Choice(["6", "8"]),
    default="6",
    help="Number of digits in generated code (default is 6).",
)
@click.option("-c", "--counter", type=int, default=0, help="Initial counter value.")
@click.option(
    "--no-enter",
    is_flag=True,
    help="Don't send an Enter keystroke after outputting the code.",
)
@click_force_option
@click.pass_context
def hotp(ctx, slot, key, digits, counter, no_enter, force):
    """
    Program an HMAC-SHA1 OATH-HOTP credential.
    """
    session = ctx.obj["session"]
    if not key:
        while True:
            key = click_prompt("Enter a secret key (base32)")
            try:
                key = parse_b32_key(key)
                break
            except Exception as e:
                click.echo(e)

    force or click.confirm(
        f"Program a HOTP credential in slot {slot}?", abort=True, err=True
    )
    try:
        session.put_configuration(
            slot,
            HotpSlotConfiguration(key)
            .imf(counter)
            .digits8(int(digits) == 8)
            .append_cr(not no_enter),
            ctx.obj["access_code"],
            ctx.obj["access_code"],
        )
    except CommandError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click_force_option
@click.pass_context
@click.option(
    "-A",
    "--new-access-code",
    metavar="HEX",
    required=False,
    help="Set a new 6 byte access code for the slot. Set to empty to use a "
    "prompt for input.",
)
@click.option(
    "--delete-access-code", is_flag=True, help="Remove access code from the slot."
)
@click.option(
    "--enter/--no-enter",
    default=True,
    show_default=True,
    help="Should send 'Enter' keystroke after slot output.",
)
@click.option(
    "-p",
    "--pacing",
    type=click.Choice(["0", "20", "40", "60"]),
    default="0",
    show_default=True,
    help="Throttle output speed by adding a delay (in ms) between characters emitted.",
)
@click.option(
    "--use-numeric-keypad",
    is_flag=True,
    show_default=True,
    help="Use scancodes for numeric keypad when sending digits."
    " Helps with some keyboard layouts. ",
)
def settings(
    ctx,
    slot,
    new_access_code,
    delete_access_code,
    enter,
    pacing,
    use_numeric_keypad,
    force,
):
    """
    Update the settings for a slot.

    Change the settings for a slot without changing the stored secret.
    All settings not specified will be written with default values.
    """
    session = ctx.obj["session"]

    if (new_access_code is not None) and delete_access_code:
        ctx.fail("--new-access-code conflicts with --delete-access-code.")

    if not session.get_config_state().is_configured(slot):
        cli_fail("Not possible to update settings on an empty slot.")

    if new_access_code is None:
        if not delete_access_code:
            new_access_code = ctx.obj["access_code"]
    else:
        if new_access_code == "":
            new_access_code = click_prompt("Enter new access code", show_default=False)

        try:
            new_access_code = parse_access_code_hex(new_access_code)
        except Exception as e:
            ctx.fail("Failed to parse access code: " + str(e))

    force or click.confirm(
        f"Update the settings for slot {slot}? "
        "All existing settings will be overwritten.",
        abort=True,
        err=True,
    )
    click.echo(f"Updating settings for slot {slot}...")

    pacing_bits = int(pacing or "0") // 20
    pacing_10ms = bool(pacing_bits & 1)
    pacing_20ms = bool(pacing_bits & 2)

    try:
        session.update_configuration(
            slot,
            UpdateConfiguration()
            .append_cr(enter)
            .use_numeric(use_numeric_keypad)
            .pacing(pacing_10ms, pacing_20ms),
            new_access_code,
            ctx.obj["access_code"],
        )
    except CommandError as e:
        _failed_to_write_msg(ctx, e)
