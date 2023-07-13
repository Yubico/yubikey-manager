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
    ALGORITHM,
    MANAGEMENT_KEY_LEN,
    CREDENTIAL_PASSWORD_LEN,
    DEFAULT_MANAGEMENT_KEY,
)
from yubikit.core.smartcard import ApduError, SW

from ..util import parse_private_key

from ..hsmauth import (
    get_hsmauth_info,
    generate_random_management_key,
    parse_touch_required,
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import click
import logging

logger = logging.getLogger(__name__)


def _parse_key(key, key_len, key_type):
    try:
        key = bytes.fromhex(key)
    except Exception:
        ValueError(key)

    if len(key) != key_len:
        raise ValueError(
            f"{key_type} must be exactly {key_len} bytes long "
            f"({key_len*2} hexadecimal digits) long"
        )
    return key


def _parse_password(pwd, pwd_len, pwd_type):
    try:
        pwd = pwd.encode()
    except Exception:
        raise ValueError(pwd)

    if len(pwd) > pwd_len:
        raise ValueError(
            "%s must be less than or equal to %d bytes long" % (pwd_type, pwd_len)
        )
    return pwd


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
    return _parse_key(
        val, ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len, "Encryption key"
    )


@click_callback()
def click_parse_mac_key(ctx, param, val):
    return _parse_key(val, ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len, "MAC key")


@click_callback()
def click_parse_credential_password(ctx, param, val):
    return _parse_password(val, CREDENTIAL_PASSWORD_LEN, "Credential password")


@click_callback()
def click_parse_card_crypto(ctx, param, val):
    return _parse_hex(val)


@click_callback()
def click_parse_context(ctx, param, val):
    return _parse_hex(val)


click_management_key_option = click.option(
    "-m",
    "--management-key",
    help="the management key",
    default=DEFAULT_MANAGEMENT_KEY,
    show_default=True,
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
    Display general status of the PIV application.
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
        f"Your YubiKey now has the default Management Key ({DEFAULT_MANAGEMENT_KEY})."
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

        click.echo("Algo\tTouch\tRetries\tLabel")

        for cred in creds:
            click.echo(
                "{0}\t{1}\t{2}\t{3}".format(
                    cred.algorithm,
                    parse_touch_required(cred.touch_required),
                    cred.counter,
                    cred.label,
                )
            )


@credentials.command()
@click.pass_context
@click.argument("label")
@click.option("-E", "--enc-key", help="ENC key", callback=click_parse_enc_key)
@click.option("-M", "--mac-key", help="MAC key", callback=click_parse_mac_key)
@click.option("-p", "--private-key", type=click.File("rb"))
@click.option("-P", "--password", help="password used to decrypt the private key")
@click.option(
    "-g", "--generate", is_flag=True, help="generate a private key on the YubiKey"
)
@click.option(
    "-c",
    "--credential-password",
    help="password to protect credential",
    callback=click_parse_credential_password,
)
@click.option(
    "-d",
    "--derivation-password",
    help="deriviation password for ENC and MAC keys",
)
@click_management_key_option
@click_touch_option
def add(
    ctx,
    label,
    enc_key,
    mac_key,
    private_key,
    password,
    generate,
    credential_password,
    derivation_password,
    management_key,
    touch,
):
    """
    Add a new credential.

    This will add a new YubiHSM Auth credential to the YubiKey.

    \b
    LABEL label for the YubiHSM Auth credential
    """

    if enc_key and mac_key and derivation_password:
        ctx.fail(
            "--enc-key and --mac-key cannot be combined with --derivation-password"
        )

    if enc_key and mac_key and private_key:
        ctx.fail("--enc-key and --mac-key cannot be combined with --private-key")

    if derivation_password and private_key:
        ctx.fail("--derivation-password cannot be combined with --private-key")

    if enc_key and not mac_key or mac_key and not enc_key:
        ctx.fail("--enc-key and --mac-key need to be combined")

    session = ctx.obj["session"]

    if not credential_password:
        credential_password = _parse_password(
            click_prompt("Enter Credential password"),
            CREDENTIAL_PASSWORD_LEN,
            "Credential password",
        )

    try:
        if enc_key and mac_key:
            session.put_credential_symmetric(
                management_key, label, enc_key, mac_key, credential_password, touch
            )
        elif derivation_password:
            session.put_credential_derived(
                management_key, label, credential_password, derivation_password, touch
            )
        elif private_key:
            data = private_key.read()
            private_key = parse_private_key(data, password)
            if not isinstance(
                private_key, ec.EllipticCurvePrivateKey
            ) or not isinstance(private_key.curve, ec.SECP256R1):
                raise CliFail(
                    "Private key must be an EC key " "with curve name secp256r1"
                )
            session.put_credential_asymmetric(
                management_key,
                label,
                private_key,
                credential_password,
                touch,
            )
        elif generate:
            session.generate_credential_asymmetric(
                management_key, label, credential_password, touch
            )

        else:
            ctx.fail(
                "--enc-key and --mac-key, --derivaion-password "
                "or --private-key required"
            )
    except ApduError as e:
        if e.sw == SW.AUTH_METHOD_BLOCKED:
            raise CliFail('A credential with label "%s" already exists.' % label)
        elif e.sw & 0xFFF0 == SW.VERIFY_FAIL_NO_RETRY:
            raise CliFail("Wrong management key, %d retries left." % (e.sw & ~0xFFF0))
        elif e.sw == SW.NO_SPACE:
            raise CliFail("No space left on the YubiKey for YubiHSM Auth credentials.")
        else:
            raise CliFail("Failed to add credential")


@credentials.command()
@click.pass_context
@click.argument("label")
@click.option("-o", "--output", type=click.File("wb"), help="file to output public key")
@click_format_option
def get_public_key(ctx, label, output, format):
    """
    Get long-term public key for an asymmetric credential.
    """

    session = ctx.obj["session"]

    try:
        public_key = session.get_public_key(label)
        key_encoding = format
        public_key_encoded = public_key.public_bytes(
            encoding=key_encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if output:
            output.write(public_key_encoded)
        else:
            click.echo(public_key_encoded, nl=False)
    except ApduError as e:
        if e.sw == SW.AUTH_METHOD_BLOCKED:
            raise CliFail("The entry is not an asymmetric credential")
        elif e.sw == SW.FILE_NOT_FOUND:
            raise CliFail("Credential not found")
        else:
            raise CliFail("Failed to get public key")


@credentials.command()
@click.pass_context
@click.argument("label")
def get_challenge(ctx, label):
    """
    Get host challenge from credential.

    For symmetric credentials this is a random 8 byte value. For asymmetric
    credentials this is EPK-OCE.
    """

    session = ctx.obj["session"]

    challenge = session.get_challenge(label).hex()
    click.echo(f"Challenge: {challenge}")


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

    force or click.confirm(
        f"Delete credential: {label} ?",
        abort=True,
        err=True,
    )

    session = ctx.obj["session"]

    try:
        session.delete_credential(management_key, label)
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            raise CliFail("Credential not found")
        elif e.sw & 0xFFF0 == SW.VERIFY_FAIL_NO_RETRY:
            raise CliFail("Wrong management key, %d retries left" % (e.sw & ~0xFFF0))
        else:
            raise CliFail("Failed to delete credential.")


@credentials.command()
@click.pass_context
@click.argument("label")
@click.option(
    "-c",
    "--credential-password",
    help="password to access credential",
    callback=click_parse_credential_password,
)
@click.option(
    "-C", "--context", help="the authentication context", callback=click_parse_context
)
@click.option(
    "-p",
    "--public-key",
    help="the public key of the YubiHSM2 device",
    type=click.File("rb"),
)
@click.option(
    "-G",
    "--card-cryptogram",
    help="the card cryptogram",
    callback=click_parse_card_crypto,
)
def calculate(ctx, label, credential_password, context, public_key, card_cryptogram):
    """
    Calculate session credentials.

    This will create session credentials based on the "context"
    and the credentials on the YubiKey. For symmetric credentials
    the "context" will be the host + HSM challenge. For asymmetric
    credentials the "context" will be EPK.OCE + EPK.SD.
    """

    if not credential_password:
        credential_password = _parse_password(
            click_prompt("Enter Credential password"),
            CREDENTIAL_PASSWORD_LEN,
            "Credential password",
        )

    try:
        session = ctx.obj["session"]
        if public_key:
            data = public_key.read()
            public_key = serialization.load_pem_public_key(data, default_backend())
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                public_key.curve, ec.SECP256R1
            ):
                raise CliFail(
                    "Public key must be an EC key " "with curve name secp256r1"
                )
            if not card_cryptogram or len(card_cryptogram) != 16:
                raise CliFail("Card crypto must be 16 bytes long")
            if not context:
                context = _parse_hex(click.prompt("Enter context"))
            if len(context) != 130:
                raise CliFail("Context must be 130 bytes long (EPK.OCE + EPK.SD)")

            session_credentials = session.calculate_session_keys_asymmetric(
                label, context, public_key, credential_password, card_cryptogram
            )
        else:
            if card_cryptogram and len(card_cryptogram) != 8:
                raise CliFail("Card crypto must be 8 bytes long")
            if not context:
                context = _parse_hex(click.prompt("Enter context"))
            if len(context) != 16:
                raise CliFail("Context must be 130 bytes long (host + HSM challenge)")

            session_credentials = session.calculate_session_keys_symmetric(
                label,
                context,
                credential_password,
                card_cryptogram,
            )

        click.echo(
            "\n".join(
                pretty_print(
                    {
                        "S-ENC": session_credentials.key_senc,
                        "S-MAC": session_credentials.key_smac,
                        "S-RMAC": session_credentials.key_srmac,
                    }
                )
            )
        )

    except ApduError as e:
        if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
            raise CliFail("Touch required")
        elif e.sw & 0xFFF0 == SW.VERIFY_FAIL_NO_RETRY:
            raise CliFail(
                "Wrong credential password, %d retries left" % (e.sw & ~0xFFF0)
            )
        elif e.sw == SW.FILE_NOT_FOUND:
            raise CliFail("Credential not found")
        else:
            raise CliFail("Failed to calculate session credentials.")


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
def change(ctx, management_key, new_management_key, generate):
    """
    Change the management key.

    Allows you to change the management key which is required to add and delete
    YubiHSM Auth credentials stored on the YubiKey.
    """

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
    except ApduError as e:
        if e.sw & 0xFFF0 == SW.VERIFY_FAIL_NO_RETRY:
            raise CliFail("Wrong management key, %d retries left." % (e.sw & ~0xFFF0))
        else:
            raise CliFail("Failed to change management key.")


@access.command()
@click.pass_context
def retries(ctx):
    """
    Get management key retries.

    This will retrieve the number of retiries left for the management key.
    """

    session = ctx.obj["session"]

    retries = session.get_management_key_retries()
    click.echo(f"Retries left for Management Key: {retries}")
