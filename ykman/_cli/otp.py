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

from base64 import b32encode
from yubikit.yubiotp import (
    SLOT,
    NDEF_TYPE,
    YubiOtpSession,
    YubiOtpSlotConfiguration,
    HmacSha1SlotConfiguration,
    StaticPasswordSlotConfiguration,
    HotpSlotConfiguration,
    UpdateConfiguration,
)
from yubikit.core import TRANSPORT, CommandError
from yubikit.core.otp import (
    MODHEX_ALPHABET,
    modhex_encode,
    modhex_decode,
    OtpConnection,
)
from yubikit.core.smartcard import SmartCardConnection

from .util import (
    CliFail,
    click_group,
    click_force_option,
    click_callback,
    click_parse_b32_key,
    click_postpone_execution,
    click_prompt,
    prompt_for_touch,
    EnumChoice,
    is_yk4_fips,
)
from .. import __version__
from ..scancodes import encode, KEYBOARD_LAYOUT
from ..otp import (
    _PrepareUploadFailed,
    _prepare_upload_key,
    is_in_fips_mode,
    generate_static_pw,
    parse_oath_key,
    parse_b32_key,
    time_challenge,
    format_oath_code,
    format_csv,
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


_WRITE_FAIL_MSG = (
    "Failed to write to the YubiKey. Make sure the device does not "
    'have restricted access (see "ykman otp --help" for more info).'
)


def _confirm_slot_overwrite(slot_state, slot):
    if slot_state.is_configured(slot):
        click.confirm(
            f"Slot {slot} is already configured. Overwrite configuration?",
            abort=True,
            err=True,
        )


def _fname(fobj):
    return getattr(fobj, "name", fobj)


@click_group(connections=[OtpConnection, SmartCardConnection])
@click.pass_context
@click_postpone_execution
@click.option(
    "--access-code",
    required=False,
    metavar="HEX",
    help='6 byte access code (use "-" as a value to prompt for input)',
)
def otp(ctx, access_code):
    """
    Manage the YubiOTP application.

    The YubiKey provides two keyboard-based slots which can each be configured
    with a credential. Several credential types are supported.

    A slot configuration may be write-protected with an access code. This
    prevents the configuration to be overwritten without the access code
    provided. Mode switching the YubiKey is not possible when a slot is
    configured with an access code. To provide an access code to commands
    which require it, use the --access-code option. Note that this option must
    be given directly after the "otp" command, before any sub-command.

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

    \b
      Remove a currently set access code from slot 2):
      $ ykman otp --access-code 0123456789ab settings 2 --delete-access-code
    """

    """
    # TODO: Require OTP for chalresp, or FW < 5.?. Require CCID for HashOTP
    dev = ctx.obj["device"]
    if dev.supports_connection(OtpConnection):
        conn = dev.open_connection(OtpConnection)
    else:
        conn = dev.open_connection(SmartCardConnection)
    ctx.call_on_close(conn.close)

    ctx.obj["session"] = YubiOtpSession(conn)
    """

    if access_code is not None:
        if access_code == "-":
            access_code = click_prompt("Enter the access code", hide_input=True)

        try:
            access_code = parse_access_code_hex(access_code)
        except Exception as e:
            ctx.fail(f"Failed to parse access code: {e}")

    ctx.obj["access_code"] = access_code


def _get_session(ctx, types=[OtpConnection, SmartCardConnection]):
    dev = ctx.obj["device"]
    for conn_type in types:
        if dev.supports_connection(conn_type):
            conn = dev.open_connection(conn_type)
            ctx.call_on_close(conn.close)
            return YubiOtpSession(conn)
    raise CliFail(
        "The connection type required for this command is not supported/enabled on the "
        "YubiKey"
    )


@otp.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the YubiKey OTP slots.
    """
    session = _get_session(ctx)
    state = session.get_config_state()
    slot1 = state.is_configured(1)
    slot2 = state.is_configured(2)

    click.echo(f"Slot 1: {slot1 and 'programmed' or 'empty'}")
    click.echo(f"Slot 2: {slot2 and 'programmed' or 'empty'}")

    if is_yk4_fips(ctx.obj["info"]):
        click.echo(f"FIPS Approved Mode: {'Yes' if is_in_fips_mode(session) else 'No'}")


@otp.command()
@click_force_option
@click.pass_context
def swap(ctx, force):
    """
    Swaps the two slot configurations.
    """
    session = _get_session(ctx)
    force or click.confirm(
        "Swap the two slots of the YubiKey?",
        abort=True,
        err=True,
    )

    click.echo("Swapping slots...")
    try:
        session.swap_slots()
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)


@otp.command()
@click_slot_argument
@click.pass_context
@click.option("-p", "--prefix", help="added before the NDEF payload, typically a URI")
@click.option(
    "-t",
    "--ndef-type",
    type=EnumChoice(NDEF_TYPE),
    default="URI",
    show_default=True,
    help="NDEF payload type",
)
def ndef(ctx, slot, prefix, ndef_type):
    """
    Configure a slot to be used over NDEF (NFC).

    \b
    If "--prefix" is not specified, a default value will be used, based on the type:
    - For URI the default value is: "https://my.yubico.com/yk/#"
    - For TEXT the default is an empty string
    """
    info = ctx.obj["info"]
    session = _get_session(ctx)
    state = session.get_config_state()
    if not info.has_transport(TRANSPORT.NFC):
        raise CliFail("This YubiKey does not support NFC.")

    if not state.is_configured(slot):
        raise CliFail(f"Slot {slot} is empty.")

    try:
        session.set_ndef_configuration(slot, prefix, ctx.obj["access_code"], ndef_type)
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)


@otp.command()
@click_slot_argument
@click_force_option
@click.pass_context
def delete(ctx, slot, force):
    """
    Deletes the configuration stored in a slot.
    """
    session = _get_session(ctx)
    state = session.get_config_state()
    if not force and not state.is_configured(slot):
        raise CliFail("Not possible to delete an empty slot.")
    force or click.confirm(
        f"Do you really want to delete the configuration of slot {slot}?",
        abort=True,
        err=True,
    )
    click.echo(f"Deleting the configuration in slot {slot}...")
    try:
        session.delete_slot(slot, ctx.obj["access_code"])
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)


@otp.command()
@click_slot_argument
@click.option(
    "-P",
    "--public-id",
    required=False,
    help="public identifier prefix",
    metavar="MODHEX",
)
@click.option(
    "-p",
    "--private-id",
    required=False,
    metavar="HEX",
    callback=parse_hex(6),
    help="6 byte private identifier",
)
@click.option(
    "-k",
    "--key",
    required=False,
    metavar="HEX",
    callback=parse_hex(16),
    help="16 byte secret key",
)
@click.option(
    "--no-enter",
    is_flag=True,
    help="don't send an Enter keystroke after emitting the OTP",
)
@click.option(
    "-S",
    "--serial-public-id",
    is_flag=True,
    required=False,
    help="use YubiKey serial number as public ID (can't be used with --public-id)",
)
@click.option(
    "-g",
    "--generate-private-id",
    is_flag=True,
    required=False,
    help="generate a random private ID (can't be used with --private-id)",
)
@click.option(
    "-G",
    "--generate-key",
    is_flag=True,
    required=False,
    help="generate a random secret key (can't be used with --key)",
)
@click.option(
    "-u",
    "--upload",
    is_flag=True,
    required=False,
    help="upload credential to YubiCloud (opens a browser, can't be used with --force)",
)
@click.option(
    "-O",
    "--config-output",
    type=click.File("a"),
    required=False,
    help="file to output the configuration to (existing file will be appended to)",
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
    config_output,
):
    """
    Program a Yubico OTP credential.
    """

    info = ctx.obj["info"]
    session = _get_session(ctx)
    serial = None

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
            try:
                serial = session.get_serial()
            except CommandError:
                raise CliFail("Serial number not set, public ID must be provided")

            public_id = modhex_encode(b"\xff\x00" + struct.pack(b">I", serial))
            click.echo(f"Using YubiKey serial as public ID: {public_id}")
        elif force:
            ctx.fail(
                "Public ID not given. Please remove the --force flag, or "
                "add the --serial-public-id flag or --public-id option."
            )
        else:
            public_id = click_prompt("Enter public ID")

    if len(public_id) % 2:
        ctx.fail("Invalid public ID, length must be a multiple of 2.")
    try:
        public_id = modhex_decode(public_id)
    except ValueError:
        ctx.fail(f"Invalid public ID, must be modhex ({MODHEX_ALPHABET}).")

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

    if upload:
        click.confirm("Upload credential to YubiCloud?", abort=True, err=True)

        try:
            upload_url = _prepare_upload_key(
                key,
                public_id,
                private_id,
                serial=info.serial,
                user_agent="ykman/" + __version__,
            )
            click.echo("Upload to YubiCloud initiated successfully.")
            logger.info("Initiated YubiCloud upload")
        except _PrepareUploadFailed as e:
            error_msg = "\n".join(e.messages())
            raise CliFail("Upload to YubiCloud failed.\n" + error_msg)

    force or click.confirm(
        f"Program a YubiOTP credential in slot {slot}?", abort=True, err=True
    )

    access_code = ctx.obj["access_code"]
    try:
        session.put_configuration(
            slot,
            YubiOtpSlotConfiguration(public_id, private_id, key).append_cr(
                not no_enter
            ),
            access_code,
            access_code,
        )
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)

    if config_output:
        serial = serial or session.get_serial()
        csv = format_csv(serial, public_id, private_id, key, access_code)
        config_output.write(csv + "\n")
        logger.info(f"Configuration parameters written to {_fname(config_output)}")

    if upload:
        logger.info("Launching browser for YubiCloud upload")
        click.echo("Opening upload form in browser: " + upload_url)
        webbrowser.open_new_tab(upload_url)


@otp.command()
@click_slot_argument
@click.argument("password", required=False)
@click.option("-g", "--generate", is_flag=True, help="generate a random password")
@click.option(
    "-l",
    "--length",
    metavar="LENGTH",
    type=click.IntRange(1, 38),
    default=38,
    show_default=True,
    help="length of generated password",
)
@click.option(
    "-k",
    "--keyboard-layout",
    type=EnumChoice(KEYBOARD_LAYOUT),
    default="MODHEX",
    show_default=True,
    help="keyboard layout to use for the static password",
)
@click.option(
    "--no-enter",
    is_flag=True,
    help="don't send an Enter keystroke after outputting the password",
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

    session = _get_session(ctx)

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
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)


@otp.command()
@click_slot_argument
@click.argument("key", required=False)
@click.option(
    "-t",
    "--touch",
    is_flag=True,
    help="require touch on the YubiKey to generate a response",
)
@click.option(
    "-T",
    "--totp",
    is_flag=True,
    required=False,
    help="use a base32 encoded key (optionally padded) for TOTP credentials",
)
@click.option(
    "-g",
    "--generate",
    is_flag=True,
    required=False,
    help="generate a random secret key (can't be used with KEY argument)",
)
@click_force_option
@click.pass_context
def chalresp(ctx, slot, key, totp, touch, force, generate):
    """
    Program a challenge-response credential.

    If KEY is not given, an interactive prompt will ask for it.

    \b
    KEY     a key given in hex (or base32, if --totp is specified)
    """
    session = _get_session(ctx)

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
        elif generate:
            key = os.urandom(20)
            if totp:
                b32key = b32encode(key).decode()
                click.echo(f"Using a randomly generated key (base32): {b32key}")
            else:
                click.echo(f"Using a randomly generated key (hex): {key.hex()}")
        elif totp:
            while True:
                key = click_prompt("Enter a secret key (base32)")
                try:
                    key = parse_b32_key(key)
                    break
                except Exception as e:
                    click.echo(e)
        else:
            key = click_prompt("Enter a secret key")
            key = parse_oath_key(key)

    cred_type = "TOTP" if totp else "challenge-response"
    force or click.confirm(
        f"Program a {cred_type} credential in slot {slot}?",
        abort=True,
        err=True,
    )
    try:
        session.put_configuration(
            slot,
            HmacSha1SlotConfiguration(key).require_touch(touch),
            ctx.obj["access_code"],
            ctx.obj["access_code"],
        )
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)


@otp.command()
@click_slot_argument
@click.argument("challenge", required=False)
@click.option(
    "-T",
    "--totp",
    is_flag=True,
    help="generate a TOTP code, use the current time if challenge is omitted",
)
@click.option(
    "-d",
    "--digits",
    type=click.Choice(["6", "8"]),
    default="6",
    help="number of digits in generated TOTP code (default: 6), "
    "ignored unless --totp is set",
)
@click.pass_context
def calculate(ctx, slot, challenge, totp, digits):
    """
    Perform a challenge-response operation.

    Send a challenge (in hex) to a YubiKey slot with a challenge-response
    credential, and read the response. Supports output as a OATH-TOTP code.
    """
    dev = ctx.obj["device"]
    if dev.transport == TRANSPORT.NFC:
        session = _get_session(ctx, [SmartCardConnection])
    else:
        # Calculate over USB is only available over OtpConnection
        session = _get_session(ctx, [OtpConnection])

    if not challenge and not totp:
        challenge = click_prompt("Enter a challenge (hex)")

    # Check that slot is not empty
    if not session.get_config_state().is_configured(slot):
        raise CliFail("Cannot perform challenge-response on an empty slot.")

    if totp:  # Challenge omitted or timestamp
        if challenge is None:
            challenge = time_challenge(int(time()))
        else:
            try:
                challenge = time_challenge(int(challenge))
            except Exception:
                logger.exception("Error parsing challenge")
                ctx.fail("Timestamp challenge for TOTP must be an integer.")
    else:  # Challenge is hex
        challenge = bytes.fromhex(challenge)

    try:
        event = Event()

        def on_keepalive(status):
            if not hasattr(on_keepalive, "prompted") and status == 2:
                prompt_for_touch()
                setattr(on_keepalive, "prompted", True)

        response = session.calculate_hmac_sha1(slot, challenge, event, on_keepalive)
        if totp:
            value = format_oath_code(response, int(digits))
        else:
            value = response.hex()

        click.echo(value)
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)


def parse_modhex_or_bcd(value):
    try:
        return True, modhex_decode(value)
    except ValueError:
        try:
            int(value)
            return False, bytes.fromhex(value)
        except ValueError:
            raise ValueError("value must be modhex or decimal")


@otp.command()
@click_slot_argument
@click.argument("key", callback=click_parse_b32_key, required=False)
@click.option(
    "-d",
    "--digits",
    type=click.Choice(["6", "8"]),
    default="6",
    help="number of digits in generated code (default is 6)",
)
@click.option("-c", "--counter", type=int, default=0, help="initial counter value")
@click.option("-i", "--identifier", help="token identifier")
@click.option(
    "--no-enter",
    is_flag=True,
    help="don't send an Enter keystroke after outputting the code",
)
@click_force_option
@click.pass_context
def hotp(ctx, slot, key, digits, counter, identifier, no_enter, force):
    """
    Program an HMAC-SHA1 OATH-HOTP credential.

    The YubiKey can be configured to output an OATH Token Identifier as a prefix
    to the OTP itself, which consists of OMP+TT+MUI. Using the "--identifier" option,
    you may specify the OMP+TT as 4 characters, the MUI as 8 characters, or the full
    OMP+TT+MUI as 12 characters. If omitted, a default value of "ubhe" will be used for
    OMP+TT, and the YubiKey serial number will be used as MUI.
    """
    session = _get_session(ctx)

    mh1 = False
    mh2 = False
    if identifier:
        if identifier == "-":
            identifier = "ubhe"
        if len(identifier) == 4:
            identifier += f"{session.get_serial():08}"
        elif len(identifier) == 8:
            identifier = "ubhe" + identifier
        if len(identifier) != 12:
            raise ValueError("Incorrect length for token identifier.")

        omp_m, omp = parse_modhex_or_bcd(identifier[:2])
        tt_m, tt = parse_modhex_or_bcd(identifier[2:4])
        mui_m, mui = parse_modhex_or_bcd(identifier[4:])
        if tt_m and not omp_m:
            raise ValueError("TT can only be modhex encoded if OMP is as well.")
        if mui_m and not (omp_m and tt_m):
            raise ValueError(
                "MUI can only be modhex encoded if OMP and TT are as well."
            )
        token_id = omp + tt + mui
        if mui_m:
            mh1 = mh2 = True
        elif tt_m:
            mh2 = True
        elif omp_m:
            mh1 = True
    else:
        token_id = b""

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
            .token_id(token_id, mh1, mh2)
            .digits8(int(digits) == 8)
            .append_cr(not no_enter),
            ctx.obj["access_code"],
            ctx.obj["access_code"],
        )
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)


@otp.command()
@click_slot_argument
@click_force_option
@click.pass_context
@click.option(
    "-A",
    "--new-access-code",
    metavar="HEX",
    required=False,
    help='a new 6 byte access code to set (use "-" as a value to prompt for input)',
)
@click.option(
    "--delete-access-code", is_flag=True, help="remove access code from the slot"
)
@click.option(
    "--enter/--no-enter",
    default=True,
    show_default=True,
    help="send an Enter keystroke after slot output",
)
@click.option(
    "-p",
    "--pacing",
    type=click.Choice(["0", "20", "40", "60"]),
    default="0",
    show_default=True,
    help="throttle output speed by adding a delay (in ms) between characters emitted",
)
@click.option(
    "--use-numeric-keypad",
    is_flag=True,
    show_default=True,
    help="use scancodes for numeric keypad when sending digits "
    "(helps for some keyboard layouts)",
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
    session = _get_session(ctx)

    if new_access_code and delete_access_code:
        ctx.fail("--new-access-code conflicts with --delete-access-code.")

    if delete_access_code and not ctx.obj["access_code"]:
        raise CliFail(
            "--delete-access-code used without providing an access code "
            '(see "ykman otp --help" for more info).'
        )

    if not session.get_config_state().is_configured(slot):
        raise CliFail("Not possible to update settings on an empty slot.")

    if new_access_code is None:
        if not delete_access_code:
            new_access_code = ctx.obj["access_code"]
    else:
        if new_access_code == "-":
            new_access_code = click_prompt(
                "Enter new access code", hide_input=True, confirmation_prompt=True
            )

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
    except CommandError:
        raise CliFail(_WRITE_FAIL_MSG)
