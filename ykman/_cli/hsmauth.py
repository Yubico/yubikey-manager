# Copyright (c) 2023 Yubico AB
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

from yubikit.core.smartcard import SmartCardConnection
from yubikit.hsmauth import (
    HsmAuthSession,
    InvalidPinError,
    ALGORITHM,
    MANAGEMENT_KEY_LEN,
    DEFAULT_MANAGEMENT_KEY,
)
from yubikit.core.smartcard import ApduError, SW

from ..util import parse_private_key, InvalidPasswordError

from ..hsmauth import (
    get_hsmauth_info,
    generate_random_management_key,
)
from .util import (
    CliFail,
    click_force_option,
    click_postpone_execution,
    click_callback,
    click_format_option,
    click_prompt,
    click_group,
    pretty_print,
)

from cryptography.hazmat.primitives import serialization

import click
import os
import logging

logger = logging.getLogger(__name__)


def handle_credential_error(e: Exception, default_exception_msg):
    if isinstance(e, InvalidPinError):
        attempts = e.attempts_remaining
        if attempts:
            raise CliFail(f"Wrong management key, {attempts} attempts remaining.")
        else:
            raise CliFail("Management key is blocked.")
    elif isinstance(e, ApduError):
        if e.sw == SW.AUTH_METHOD_BLOCKED:
            raise CliFail("A credential with the provided label already exists.")
        elif e.sw == SW.NO_SPACE:
            raise CliFail("No space left on the YubiKey for YubiHSM Auth credentials.")
        elif e.sw == SW.FILE_NOT_FOUND:
            raise CliFail("Credential with the provided label was not found.")
        elif e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
            raise CliFail("The device was not touched.")
    raise CliFail(default_exception_msg)


def _parse_touch_required(touch_required: bool) -> str:
    if touch_required:
        return "On"
    else:
        return "Off"


def _parse_algorithm(algorithm: ALGORITHM) -> str:
    if algorithm == ALGORITHM.AES128_YUBICO_AUTHENTICATION:
        return "Symmetric"
    else:
        return "Asymmetric"


def _parse_key(key, key_len, key_type):
    try:
        key = bytes.fromhex(key)
    except Exception:
        ValueError(key)

    if len(key) != key_len:
        raise ValueError(
            f"{key_type} must be exactly {key_len} bytes long "
            f"({key_len * 2} hexadecimal digits) long"
        )
    return key


def _parse_hex(hex):
    try:
        val = bytes.fromhex(hex)
        return val
    except Exception:
        raise ValueError(hex)


@click_callback()
def click_parse_management_key(ctx, param, val):
    return _parse_key(val, MANAGEMENT_KEY_LEN, "Management key")


@click_callback()
def click_parse_enc_key(ctx, param, val):
    return _parse_key(val, ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len, "ENC key")


@click_callback()
def click_parse_mac_key(ctx, param, val):
    return _parse_key(val, ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len, "MAC key")


@click_callback()
def click_parse_card_crypto(ctx, param, val):
    return _parse_hex(val)


@click_callback()
def click_parse_context(ctx, param, val):
    return _parse_hex(val)


def _prompt_management_key(prompt="Enter a management key [blank to use default key]"):
    management_key = click_prompt(
        prompt, default="", hide_input=True, show_default=False
    )
    if management_key == "":
        return DEFAULT_MANAGEMENT_KEY

    return _parse_key(management_key, MANAGEMENT_KEY_LEN, "Management key")


def _prompt_credential_password(prompt="Enter credential password"):
    credential_password = click_prompt(
        prompt, default="", hide_input=True, show_default=False
    )

    return credential_password


def _prompt_symmetric_key(type):
    symmetric_key = click_prompt(f"Enter {type}", default="", show_default=False)

    return _parse_key(
        symmetric_key, ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len, "ENC key"
    )


def _fname(fobj):
    return getattr(fobj, "name", fobj)


click_credential_password_option = click.option(
    "-c", "--credential-password", help="password to protect credential"
)

click_management_key_option = click.option(
    "-m",
    "--management-key",
    help="the management key",
    callback=click_parse_management_key,
)

click_touch_option = click.option(
    "-t", "--touch", is_flag=True, help="require touch on YubiKey to access credential"
)


@click_group(connections=[SmartCardConnection])
@click.pass_context
@click_postpone_execution
def hsmauth(ctx):
    """
    Manage the YubiHSM Auth application


    """
    dev = ctx.obj["device"]
    conn = dev.open_connection(SmartCardConnection)
    ctx.call_on_close(conn.close)
    ctx.obj["session"] = HsmAuthSession(conn)


@hsmauth.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the YubiHSM Auth application.
    """
    info = get_hsmauth_info(ctx.obj["session"])
    click.echo("\n".join(pretty_print(info)))


@hsmauth.command()
@click.pass_context
@click_force_option
def reset(ctx, force):
    """
    Reset all YubiHSM Auth data.

    This action will wipe all data and restore factory setting for
    the YubiHSM Auth application on the YubiKey.
    """

    force or click.confirm(
        "WARNING! This will delete all stored YubiHSM Auth data and restore factory "
        "setting. Proceed?",
        abort=True,
        err=True,
    )

    click.echo("Resetting YubiHSM Auth data...")
    ctx.obj["session"].reset()

    click.echo("Success! All YubiHSM Auth data have been cleared from the YubiKey.")
    click.echo(
        "Your YubiKey now has the default Management Key"
        f"({DEFAULT_MANAGEMENT_KEY.hex()})."
    )


@hsmauth.group()
def credentials():
    """Manage YubiHSM Auth credentials."""


@credentials.command()
@click.pass_context
def list(ctx):
    """
    List all credentials.

    List all credentials stored on the YubiKey.
    """
    session = ctx.obj["session"]
    creds = session.list_credentials()

    if len(creds) == 0:
        click.echo("No items found")
    else:
        click.echo(f"Found {len(creds)} item(s)")

        max_size_label = max(len(cred.label) for cred in creds)
        max_size_type = (
            10
            if any(
                c.algorithm == ALGORITHM.EC_P256_YUBICO_AUTHENTICATION for c in creds
            )
            else 9
        )

        format_str = "{0: <{label_width}}\t{1: <{type_width}}\t{2}\t{3}"

        click.echo(
            format_str.format(
                "Label",
                "Type",
                "Touch",
                "Retries",
                label_width=max_size_label,
                type_width=max_size_type,
            )
        )

        for cred in creds:
            click.echo(
                format_str.format(
                    cred.label,
                    _parse_algorithm(cred.algorithm),
                    _parse_touch_required(cred.touch_required),
                    cred.counter,
                    label_width=max_size_label,
                    type_width=max_size_type,
                )
            )


@credentials.command()
@click.pass_context
@click.argument("label")
@click_credential_password_option
@click_management_key_option
@click_touch_option
def generate(ctx, label, credential_password, management_key, touch):
    """Generate an asymmetric credential.

    This will generate an asymmetric YubiHSM Auth credential
    (private key) on the YubiKey.

    \b
    LABEL label for the YubiHSM Auth credential
    """

    if not credential_password:
        credential_password = _prompt_credential_password()

    if not management_key:
        management_key = _prompt_management_key()

    session = ctx.obj["session"]

    try:
        session.generate_credential_asymmetric(
            management_key, label, credential_password, touch
        )
    except Exception as e:
        handle_credential_error(
            e, default_exception_msg="Failed to generate asymmetric credential."
        )


@credentials.command("import")
@click.pass_context
@click.argument("label")
@click.argument("private-key", type=click.File("rb"), metavar="PRIVATE-KEY")
@click.option("-p", "--password", help="password used to decrypt the private key")
@click_credential_password_option
@click_management_key_option
@click_touch_option
def import_credential(
    ctx, label, private_key, password, credential_password, management_key, touch
):
    """Import an asymmetric credential.

    This will import a private key as an asymmetric YubiHSM Auth credential
    to the YubiKey.

    \b
    LABEL        label for the YubiHSM Auth credential
    PRIVATE-KEY  file containing the private key (use '-' to use stdin)
    """
    if not credential_password:
        credential_password = _prompt_credential_password()

    if not management_key:
        management_key = _prompt_management_key()

    session = ctx.obj["session"]

    data = private_key.read()

    while True:
        if password is not None:
            password = password.encode()
        try:
            private_key = parse_private_key(data, password)
        except InvalidPasswordError:
            logger.debug("Error parsing key", exc_info=True)
            if password is None:
                password = click_prompt(
                    "Enter password to decrypt key",
                    default="",
                    hide_input=True,
                    show_default=False,
                )
                continue
            else:
                password = None
                click.echo("Wrong password.")
            continue
        break

    try:
        session.put_credential_asymmetric(
            management_key,
            label,
            private_key,
            credential_password,
            touch,
        )
    except Exception as e:
        handle_credential_error(
            e, default_exception_msg="Failed to import asymmetric credential."
        )


@credentials.command()
@click.pass_context
@click.argument("label")
@click.argument("public-key-output", type=click.File("wb"), metavar="PUBLIC-KEY")
@click_format_option
def export(ctx, label, public_key_output, format):
    """Export the public key corresponding to an asymmetric credential.

    This will export the long-term public key corresponding to the
    asymmetric YubiHSM Auth credential stored on the YubiKey.

    \b
    LABEL      label for the YubiHSM Auth credential
    PUBLIC-KEY file to write the public key to (use '-' to use stdout)
    """

    session = ctx.obj["session"]

    try:
        public_key = session.get_public_key(label)
        key_encoding = format
        public_key_encoded = public_key.public_bytes(
            encoding=key_encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_key_output.write(public_key_encoded)

        logger.info(f"Public key for {label} written to {_fname(public_key_output)}")
    except ApduError as e:
        if e.sw == SW.AUTH_METHOD_BLOCKED:
            raise CliFail("The entry is not an asymmetric credential.")
        elif e.sw == SW.FILE_NOT_FOUND:
            raise CliFail("Credential not found.")
        else:
            raise CliFail("Unable to export public key.")


@credentials.command()
@click.pass_context
@click.argument("label")
@click.option("-E", "--enc-key", help="the ENC key", callback=click_parse_enc_key)
@click.option("-M", "--mac-key", help="the MAC key", callback=click_parse_mac_key)
@click.option(
    "-g", "--generate", is_flag=True, help="generate a random encryption and mac key"
)
@click_credential_password_option
@click_management_key_option
@click_touch_option
def symmetric(
    ctx, label, credential_password, management_key, enc_key, mac_key, generate, touch
):
    """Import a symmetric credential.

    This will import an encryption and mac key as a symmetric YubiHSM Auth credential on
    the YubiKey.

    \b
    LABEL  label for the YubiHSM Auth credential
    """

    if not credential_password:
        credential_password = _prompt_credential_password()

    if not management_key:
        management_key = _prompt_management_key()

    if generate and (enc_key or mac_key):
        ctx.fail("--enc-key and --mac-key cannot be combined with --generate")

    if generate:
        enc_key = os.urandom(ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len)
        mac_key = os.urandom(ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len)
        click.echo("Generated ENC and MAC keys:")
        click.echo("\n".join(pretty_print({"ENC-KEY": enc_key, "MAC-KEY": mac_key})))

    if not enc_key:
        enc_key = _prompt_symmetric_key("ENC key")

    if not mac_key:
        mac_key = _prompt_symmetric_key("MAC key")

    session = ctx.obj["session"]

    try:
        session.put_credential_symmetric(
            management_key,
            label,
            enc_key,
            mac_key,
            credential_password,
            touch,
        )

    except Exception as e:
        handle_credential_error(
            e, default_exception_msg="Failed to import symmetric credential."
        )


@credentials.command()
@click.pass_context
@click.argument("label")
@click.option(
    "-d", "--derivation-password", help="deriviation password for ENC and MAC keys"
)
@click_credential_password_option
@click_management_key_option
@click_touch_option
def derive(ctx, label, derivation_password, credential_password, management_key, touch):
    """Import a symmetric credential derived from a password.

    This will import a symmetric YubiHSM Auth credential by deriving
    ENC and MAC keys from a password.

    \b
    LABEL  label for the YubiHSM Auth credential
    """

    if not credential_password:
        credential_password = _prompt_credential_password()

    if not management_key:
        management_key = _prompt_management_key()

    if not derivation_password:
        derivation_password = click_prompt(
            "Enter derivation password", default="", show_default=False
        )

    session = ctx.obj["session"]

    try:
        session.put_credential_derived(
            management_key, label, derivation_password, credential_password, touch
        )
    except Exception as e:
        handle_credential_error(
            e, default_exception_msg="Failed to import symmetric credential."
        )


@credentials.command()
@click.pass_context
@click.argument("label")
@click_management_key_option
@click_force_option
def delete(ctx, label, management_key, force):
    """
    Delete a credential.

    This will delete a YubiHSM Auth credential from the YubiKey.

    \b
    LABEL a label to match a single credential (as shown in "list")
    """

    if not management_key:
        management_key = _prompt_management_key()

    force or click.confirm(
        f"Delete credential: {label} ?",
        abort=True,
        err=True,
    )

    session = ctx.obj["session"]

    try:
        session.delete_credential(management_key, label)
    except Exception as e:
        handle_credential_error(
            e,
            default_exception_msg="Failed to delete credential.",
        )


@hsmauth.group()
def access():
    """Manage Management Key for YubiHSM Auth"""


@access.command()
@click.pass_context
@click.option(
    "-m",
    "--management-key",
    help="current management key",
    default=DEFAULT_MANAGEMENT_KEY,
    show_default=True,
    callback=click_parse_management_key,
)
@click.option(
    "-n",
    "--new-management-key",
    help="a new management key to set",
    callback=click_parse_management_key,
)
@click.option(
    "-g",
    "--generate",
    is_flag=True,
    help="generate a random management key "
    "(can't be used with --new-management-key)",
)
def change_management_key(ctx, management_key, new_management_key, generate):
    """
    Change the management key.

    Allows you to change the management key which is required to add and delete
    YubiHSM Auth credentials stored on the YubiKey.
    """

    if not management_key:
        management_key = _prompt_management_key(
            "Enter current management key [blank to use default key]"
        )

    session = ctx.obj["session"]

    # Can't combine new key with generate.
    if new_management_key and generate:
        ctx.fail("Invalid options: --new-management-key conflicts with --generate")

    if not new_management_key:
        if generate:
            new_management_key = generate_random_management_key()
            click.echo(f"Generated management key: {new_management_key.hex()}")
        else:
            try:
                new_management_key = bytes.fromhex(
                    click_prompt(
                        "Enter the new management key",
                        hide_input=True,
                        confirmation_prompt=True,
                    )
                )
            except Exception:
                ctx.fail("New management key has the wrong format.")

    if len(new_management_key) != MANAGEMENT_KEY_LEN:
        raise CliFail(
            "Management key has the wrong length (expected %d bytes)"
            % MANAGEMENT_KEY_LEN
        )

    try:
        session.put_management_key(management_key, new_management_key)
    except Exception as e:
        handle_credential_error(
            e, default_exception_msg="Failed to change management key."
        )
