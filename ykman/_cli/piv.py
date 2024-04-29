# Copyright (c) 2017 Yubico AB
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

from yubikit.core import NotSupportedError
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import CAPABILITY
from yubikit.piv import (
    PivSession,
    InvalidPinError,
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    OBJECT_ID,
    SLOT,
    PIN_POLICY,
    TOUCH_POLICY,
    DEFAULT_MANAGEMENT_KEY,
)
from yubikit.core.smartcard import ApduError, SW

from ..util import (
    get_leaf_certificates,
    parse_private_key,
    parse_certificates,
    InvalidPasswordError,
)
from ..piv import (
    get_piv_info,
    get_pivman_data,
    get_pivman_protected_data,
    pivman_set_mgm_key,
    pivman_change_pin,
    pivman_set_pin_attempts,
    derive_management_key,
    generate_random_management_key,
    generate_chuid,
    generate_ccc,
    check_key,
    generate_self_signed_certificate,
    generate_csr,
)
from .util import (
    CliFail,
    click_group,
    click_force_option,
    click_format_option,
    click_postpone_execution,
    click_callback,
    click_prompt,
    prompt_timeout,
    EnumChoice,
    pretty_print,
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

import click
import datetime
import logging


logger = logging.getLogger(__name__)


@click_callback()
def click_parse_piv_slot(ctx, param, val):
    try:
        return SLOT[val.upper().replace("-", "_")]
    except KeyError:
        try:
            return SLOT(int(val, 16))
        except Exception:
            raise ValueError(val)


@click_callback()
def click_parse_piv_object(ctx, param, val):
    if val.upper() == "CCC":
        return OBJECT_ID.CAPABILITY
    try:
        return OBJECT_ID[val.upper().replace("-", "_")]
    except KeyError:
        try:
            return int(val, 16)
        except Exception:
            raise ValueError(val)


@click_callback()
def click_parse_management_key(ctx, param, val):
    try:
        key = bytes.fromhex(val)
        if key and len(key) not in (16, 24, 32):
            raise ValueError(
                "Management key must be exactly 16, 24, or 32 bytes "
                "(32, 48, or 64 hexadecimal digits) long."
            )
        return key
    except Exception:
        raise ValueError(val)


@click_callback()
def click_parse_hash(ctx, param, val):
    try:
        return getattr(hashes, val)
    except AttributeError:
        raise ValueError(val)


click_slot_argument = click.argument("slot", callback=click_parse_piv_slot)
click_object_argument = click.argument(
    "object_id", callback=click_parse_piv_object, metavar="OBJECT"
)
click_management_key_option = click.option(
    "-m",
    "--management-key",
    help="the management key",
    callback=click_parse_management_key,
)
click_pin_option = click.option("-P", "--pin", help="PIN code")
click_pin_policy_option = click.option(
    "--pin-policy",
    type=EnumChoice(PIN_POLICY),
    default=PIN_POLICY.DEFAULT.name,
    help="PIN policy for slot",
)
click_touch_policy_option = click.option(
    "--touch-policy",
    type=EnumChoice(TOUCH_POLICY),
    default=TOUCH_POLICY.DEFAULT.name,
    help="touch policy for slot",
)
click_hash_option = click.option(
    "-a",
    "--hash-algorithm",
    type=click.Choice(["SHA256", "SHA384", "SHA512"], case_sensitive=False),
    default="SHA256",
    show_default=True,
    help="hash algorithm",
    callback=click_parse_hash,
)


def _fname(fobj):
    return getattr(fobj, "name", fobj)


@click_group(connections=[SmartCardConnection])
@click.pass_context
@click_postpone_execution
def piv(ctx):
    """
    Manage the PIV application.

    Examples:

    \b
      Generate an ECC P-256 private key and a self-signed certificate in
      slot 9a:
      $ ykman piv keys generate --algorithm ECCP256 9a pubkey.pem
      $ ykman piv certificates generate --subject "CN=yubico" 9a pubkey.pem

    \b
      Change the PIN from 123456 to 654321:
      $ ykman piv access change-pin --pin 123456 --new-pin 654321

    \b
      Reset all PIV data and restore default settings:
      $ ykman piv reset
    """

    dev = ctx.obj["device"]
    conn = dev.open_connection(SmartCardConnection)
    ctx.call_on_close(conn.close)
    session = PivSession(conn)
    ctx.obj["session"] = session
    ctx.obj["pivman_data"] = get_pivman_data(session)
    info = ctx.obj["info"]
    ctx.obj["fips_unready"] = (
        CAPABILITY.PIV in info.fips_capable and CAPABILITY.PIV not in info.fips_approved
    )


@piv.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the PIV application.
    """
    info = ctx.obj["info"]
    data = get_piv_info(ctx.obj["session"])
    if CAPABILITY.PIV in info.fips_capable:
        # This is a bit ugly as it makes assumptions about the structure of data
        data[0]["FIPS approved"] = CAPABILITY.PIV in info.fips_approved
    click.echo("\n".join(pretty_print(data)))


@piv.command()
@click.pass_context
@click_force_option
def reset(ctx, force):
    """
    Reset all PIV data.

    This action will wipe all data and restore factory settings for
    the PIV application on the YubiKey.
    """
    info = ctx.obj["info"]
    if CAPABILITY.PIV in info.reset_blocked:
        raise CliFail(
            "Cannot perform PIV reset when biometrics are configured, "
            "use 'ykman config reset' for full factory reset."
        )

    force or click.confirm(
        "WARNING! This will delete all stored PIV data and restore factory "
        "settings. Proceed?",
        abort=True,
        err=True,
    )

    click.echo("Resetting PIV data...")
    ctx.obj["session"].reset()

    click.echo("Success! All PIV data have been cleared from the YubiKey.")
    click.echo("Your YubiKey now has the default PIN, PUK and Management Key:")
    click.echo("\tPIN:\t123456")
    click.echo("\tPUK:\t12345678")
    click.echo("\tManagement Key:\t010203040506070801020304050607080102030405060708")


@piv.group()
def access():
    """Manage PIN, PUK, and Management Key."""


@access.command("set-retries")
@click.pass_context
@click.argument("pin-retries", type=click.IntRange(1, 255), metavar="PIN-RETRIES")
@click.argument("puk-retries", type=click.IntRange(0, 255), metavar="PUK-RETRIES")
@click_management_key_option
@click_pin_option
@click_force_option
def set_pin_retries(ctx, management_key, pin, pin_retries, puk_retries, force):
    """
    Set the number of PIN and PUK retry attempts.

    NOTE: This will reset the PIN and PUK to their factory defaults.
    """
    session = ctx.obj["session"]
    info = ctx.obj["info"]
    if CAPABILITY.PIV in info.fips_capable:
        if not (
            session.get_pin_metadata().default_value
            and session.get_puk_metadata().default_value
        ):
            raise CliFail(
                "Retry attempts must be set before PIN/PUK have been changed."
            )

    _ensure_authenticated(
        ctx, pin, management_key, require_pin_and_key=True, no_prompt=force
    )
    click.echo("WARNING: This will reset the PIN and PUK to the factory defaults!")
    force or click.confirm(
        f"Set the number of PIN and PUK retry attempts to: {pin_retries} "
        f"{puk_retries}?",
        abort=True,
        err=True,
    )
    try:
        pivman_set_pin_attempts(session, pin_retries, puk_retries)
        click.echo("Default PINs are set:")
        click.echo("\tPIN:\t123456")
        click.echo("\tPUK:\t12345678")
    except Exception:
        raise CliFail("Setting pin retries failed.")


def _do_change_pin_puk(pin_complexity, name, current, new, fn):
    def validate_pin_length(pin, prefix):
        unit = "characters" if pin_complexity else "bytes"
        pin_len = len(pin) if pin_complexity else len(pin.encode())
        if not 6 <= pin_len <= 8:
            raise CliFail(f"{prefix} {name} must be between 6 and 8 {unit} long.")

    validate_pin_length(current, "Current")
    validate_pin_length(new, "New")

    try:
        fn()
        click.echo(f"New {name} set.")
    except InvalidPinError as e:
        attempts = e.attempts_remaining
        if attempts:
            raise CliFail(f"{name} change failed - %d tries left." % attempts)
        else:
            raise CliFail(f"{name} is blocked.")
    except ApduError as e:
        if e.sw == SW.CONDITIONS_NOT_SATISFIED:
            raise CliFail(f"{name} does not meet complexity requirement.")
        raise


@access.command("change-pin")
@click.pass_context
@click.option("-P", "--pin", help="current PIN code")
@click.option("-n", "--new-pin", help="a new PIN to set")
def change_pin(ctx, pin, new_pin):
    """
    Change the PIN code.

    The PIN must be between 6 and 8 bytes long, and supports any type of
    alphanumeric characters. For cross-platform compatibility, numeric PINs are
    recommended.
    """
    info = ctx.obj["info"]
    session = ctx.obj["session"]

    if not pin:
        pin = _prompt_pin("Enter the current PIN")
    if not new_pin:
        new_pin = click_prompt(
            "Enter the new PIN",
            default="",
            hide_input=True,
            show_default=False,
            confirmation_prompt=True,
        )

    _do_change_pin_puk(
        info.pin_complexity,
        "PIN",
        pin,
        new_pin,
        lambda: pivman_change_pin(session, pin, new_pin),
    )


@access.command("change-puk")
@click.pass_context
@click.option("-p", "--puk", help="current PUK code")
@click.option("-n", "--new-puk", help="a new PUK code to set")
def change_puk(ctx, puk, new_puk):
    """
    Change the PUK code.

    If the PIN is lost or blocked it can be reset using a PUK.
    The PUK must be between 6 and 8 bytes long, and supports any type of
    alphanumeric characters.
    """
    info = ctx.obj["info"]
    session = ctx.obj["session"]

    if not puk:
        puk = _prompt_pin("Enter the current PUK")
    if not new_puk:
        new_puk = click_prompt(
            "Enter the new PUK",
            default="",
            hide_input=True,
            show_default=False,
            confirmation_prompt=True,
        )

    _do_change_pin_puk(
        info.pin_complexity,
        "PUK",
        puk,
        new_puk,
        lambda: session.change_puk(puk, new_puk),
    )


@access.command("change-management-key")
@click.pass_context
@click_pin_option
@click.option(
    "-t",
    "--touch",
    is_flag=True,
    help="require touch on YubiKey when prompted for management key",
)
@click.option(
    "-n",
    "--new-management-key",
    help="a new management key to set",
    callback=click_parse_management_key,
)
@click.option(
    "-m",
    "--management-key",
    help="current management key",
    callback=click_parse_management_key,
)
@click.option(
    "-a",
    "--algorithm",
    help="management key algorithm",
    type=EnumChoice(MANAGEMENT_KEY_TYPE),
)
@click.option(
    "-p",
    "--protect",
    is_flag=True,
    help="store new management key on the YubiKey, protected by PIN "
    "(a random key will be used if no key is provided)",
)
@click.option(
    "-g",
    "--generate",
    is_flag=True,
    help="generate a random management key "
    "(implied by --protect unless --new-management-key is also given, "
    "can't be used with --new-management-key)",
)
@click_force_option
def change_management_key(
    ctx,
    management_key,
    algorithm,
    pin,
    new_management_key,
    touch,
    protect,
    generate,
    force,
):
    """
    Change the management key.

    Management functionality is guarded by a management key.
    This key is required for administrative tasks, such as generating key pairs.
    A random key may be generated and stored on the YubiKey, protected by PIN.
    """
    session = ctx.obj["session"]

    if not algorithm:
        try:
            algorithm = session.get_management_key_metadata().key_type
        except NotSupportedError:
            algorithm = MANAGEMENT_KEY_TYPE.TDES

    info = ctx.obj["info"]
    if CAPABILITY.PIV in info.fips_capable and algorithm in (MANAGEMENT_KEY_TYPE.TDES,):
        raise CliFail(f"{algorithm.name} not supported on YubiKey FIPS.")

    pin_verified = _ensure_authenticated(
        ctx,
        pin,
        management_key,
        require_pin_and_key=protect,
        mgm_key_prompt="Enter the current management key [blank to use default key]",
        no_prompt=force,
    )

    # Can't combine new key with generate.
    if new_management_key and generate:
        raise CliFail("Invalid options: --new-management-key conflicts with --generate")

    # Touch not supported on NEO.
    if touch and session.version < (4, 0, 0):
        raise CliFail("Require touch not supported on this YubiKey.")

    # If an old stored key needs to be cleared, the PIN is needed.
    pivman = ctx.obj["pivman_data"]
    if not pin_verified and pivman.has_stored_key:
        if pin:
            _verify_pin(ctx, session, pivman, pin, no_prompt=force)
        elif not force:
            click.confirm(
                "The current management key is stored on the YubiKey"
                " and will not be cleared if no PIN is provided. Continue?",
                abort=True,
                err=True,
            )

    if not new_management_key:
        if protect or generate:
            new_management_key = generate_random_management_key(algorithm)
            if not protect:
                click.echo(f"Generated management key: {new_management_key.hex()}")
        elif force:
            raise CliFail(
                "New management key not given. Remove the --force "
                "flag, or set the --generate flag or the "
                "--new-management-key option."
            )
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
                raise CliFail("New management key has the wrong format.")

    if len(new_management_key) != algorithm.key_len:
        raise CliFail(
            "Management key has the wrong length (expected %d bytes)"
            % algorithm.key_len
        )

    try:
        pivman_set_mgm_key(
            session, new_management_key, algorithm, touch=touch, store_on_device=protect
        )
    except ApduError:
        raise CliFail("Changing the management key failed.")


@access.command("unblock-pin")
@click.pass_context
@click.option("-p", "--puk", required=False)
@click.option("-n", "--new-pin", required=False, metavar="NEW-PIN")
def unblock_pin(ctx, puk, new_pin):
    """
    Unblock the PIN (using PUK).
    """
    session = ctx.obj["session"]
    if not puk:
        puk = click_prompt("Enter PUK", default="", show_default=False, hide_input=True)
    if not new_pin:
        new_pin = click_prompt(
            "Enter a new PIN",
            default="",
            show_default=False,
            hide_input=True,
            confirmation_prompt=True,
        )
    try:
        session.unblock_pin(puk, new_pin)
        click.echo("PIN unblocked")
    except InvalidPinError as e:
        attempts = e.attempts_remaining
        if attempts:
            raise CliFail("PIN unblock failed - %d tries left." % attempts)
        else:
            raise CliFail("PUK is blocked.")
    except ApduError as e:
        if e.sw == SW.CONDITIONS_NOT_SATISFIED:
            raise CliFail("PIN does not meet complexity requirement.")
        raise


@piv.group()
def keys():
    """
    Manage private keys.
    """


@keys.command("generate")
@click.pass_context
@click_management_key_option
@click_pin_option
@click.option(
    "-a",
    "--algorithm",
    help="algorithm to use in key generation",
    type=EnumChoice(KEY_TYPE),
    default=KEY_TYPE.RSA2048.name,
    show_default=True,
)
@click_format_option
@click_pin_policy_option
@click_touch_policy_option
@click_slot_argument
@click.argument("public-key-output", type=click.File("wb"), metavar="PUBLIC-KEY")
def generate_key(
    ctx,
    slot,
    public_key_output,
    management_key,
    pin,
    algorithm,
    format,
    pin_policy,
    touch_policy,
):
    """
    Generate an asymmetric key pair.

    The private key is generated on the YubiKey, and written to one of the slots.

    \b
    SLOT        PIV slot of the private key
    PUBLIC-KEY  file containing the generated public key (use '-' to use stdout)
    """

    if ctx.obj["fips_unready"]:
        raise CliFail(
            "YubiKey FIPS must be in FIPS approved mode prior to key generation"
        )
    _check_key_support_fips(ctx, algorithm, pin_policy)

    session = ctx.obj["session"]
    _ensure_authenticated(ctx, pin, management_key)

    public_key = session.generate_key(slot, algorithm, pin_policy, touch_policy)

    key_encoding = format
    public_key_output.write(
        public_key.public_bytes(
            encoding=key_encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    logger.info(
        f"Private key generated in slot {slot}, public key written to "
        f"{_fname(public_key_output)}"
    )


@keys.command("import")
@click.pass_context
@click_pin_option
@click_management_key_option
@click_pin_policy_option
@click_touch_policy_option
@click_slot_argument
@click.argument("private-key", type=click.File("rb"), metavar="PRIVATE-KEY")
@click.option("-p", "--password", help="password used to decrypt the private key")
def import_key(
    ctx, management_key, pin, slot, private_key, pin_policy, touch_policy, password
):
    """
    Import a private key from file.

    Write a private key to one of the PIV slots on the YubiKey.

    \b
    SLOT         PIV slot of the private key
    PRIVATE-KEY  file containing the private key (use '-' to use stdin)
    """

    if ctx.obj["fips_unready"]:
        raise CliFail("YubiKey FIPS must be in FIPS approved mode prior to key import")

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

    _check_key_support_fips(
        ctx, KEY_TYPE.from_public_key(private_key.public_key()), pin_policy
    )

    _ensure_authenticated(ctx, pin, management_key)
    session.put_key(slot, private_key, pin_policy, touch_policy)


@keys.command()
@click.pass_context
@click_format_option
@click_slot_argument
@click.argument("certificate", type=click.File("wb"), metavar="CERTIFICATE")
def attest(ctx, slot, certificate, format):
    """
    Generate an attestation certificate for a key pair.

    Attestation is used to show that an asymmetric key was generated on the
    YubiKey and therefore doesn't exist outside the device.

    \b
    SLOT         PIV slot of the private key
    CERTIFICATE  file to write attestation certificate to (use '-' to use stdout)
    """
    session = ctx.obj["session"]
    try:
        cert = session.attest_key(slot)
    except ApduError:
        raise CliFail("Attestation failed.")
    certificate.write(cert.public_bytes(encoding=format))
    logger.info(
        f"Attestation certificate for slot {slot} written to {_fname(certificate)}"
    )


@keys.command("info")
@click.pass_context
@click_slot_argument
def metadata(ctx, slot):
    """
    Show metadata about a private key.

    This will show what type of key is stored in a specific slot,
    whether it was imported into the YubiKey, or generated on-chip,
    and what the PIN and Touch policies are for using the key.

    \b
    SLOT        PIV slot of the private key
    """

    session = ctx.obj["session"]
    try:
        metadata = session.get_slot_metadata(slot)
        info = {
            "Key slot": slot,
            "Algorithm": metadata.key_type.name,
            "Origin": "GENERATED" if metadata.generated else "IMPORTED",
            "PIN required for use": metadata.pin_policy.name,
            "Touch required for use": metadata.touch_policy.name,
        }
        click.echo("\n".join(pretty_print(info)))
    except ApduError as e:
        if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
            raise CliFail(f"No key stored in slot {slot}.")
        raise


@keys.command()
@click.pass_context
@click_format_option
@click_slot_argument
@click.option(
    "-v",
    "--verify",
    is_flag=True,
    help="verify that the public key matches the private key in the slot",
)
@click.option("-P", "--pin", help="PIN code (used for --verify)")
@click.argument("public-key-output", type=click.File("wb"), metavar="PUBLIC-KEY")
def export(ctx, slot, public_key_output, format, verify, pin):
    """
    Export a public key corresponding to a stored private key.

    This command uses several different mechanisms for exporting the public key
    corresponding to a stored private key, which may fail.
    If a certificate is stored in the slot it is assumed to contain the correct public
    key. If this is not the case, the wrong public key will be returned.

    The --verify flag can be used to verify that the public key being returned matches
    the private key, by using the slot to create and verify a signature. This may
    require the PIN to be provided.

    \b
    SLOT        PIV slot of the private key
    PUBLIC-KEY  file to write the public key to (use '-' to use stdout)
    """
    session = ctx.obj["session"]
    try:  # Prefer metadata if available
        public_key = session.get_slot_metadata(slot).public_key
        logger.debug("Public key read from YubiKey")
    except ApduError as e:
        if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
            raise CliFail(f"No key stored in slot {slot}.")
        raise CliFail(f"Unable to export public key from slot {slot}.")
    except NotSupportedError:
        try:  # Try attestation
            public_key = session.attest_key(slot).public_key()
            logger.debug("Public key read using attestation")
        except (NotSupportedError, ApduError):
            try:  # Read from stored certificate
                public_key = session.get_certificate(slot).public_key()
                logger.debug("Public key read from stored certificate")
                if verify:  # Only needed when read from certificate

                    def do_verify():
                        with prompt_timeout(timeout=1.0):
                            if not check_key(session, slot, public_key):
                                raise CliFail(
                                    "This public key is not tied to the private key in "
                                    f"slot {slot}."
                                )

                    _verify_pin_if_needed(ctx, session, do_verify, pin)
            except ApduError:
                raise CliFail(f"Unable to export public key from slot {slot}.")

    key_encoding = format
    public_key_output.write(
        public_key.public_bytes(
            encoding=key_encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    logger.info(f"Public key for slot {slot} written to {_fname(public_key_output)}")


@keys.command("move")
@click.pass_context
@click_management_key_option
@click_pin_option
@click.argument("source", callback=click_parse_piv_slot)
@click.argument("dest", callback=click_parse_piv_slot)
def move_key(ctx, management_key, pin, source, dest):
    """
    Moves a key.

    Moves a key from one PIV slot into another.

    \b
    SOURCE            PIV slot of the key to move
    DEST              PIV slot to move the key into
    """
    if source == dest:
        raise CliFail("SOURCE must be different from DEST")
    session = ctx.obj["session"]
    _ensure_authenticated(ctx, pin, management_key)
    try:
        session.move_key(source, dest)
    except ApduError as e:
        if e.sw == SW.INCORRECT_PARAMETERS:
            raise CliFail("DEST slot is not empty")
        if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
            raise CliFail("No key in SOURCE slot")
        raise


@keys.command("delete")
@click.pass_context
@click_management_key_option
@click_pin_option
@click_slot_argument
def delete_key(ctx, management_key, pin, slot):
    """
    Delete a key.

    Delete a key from a PIV slot on the YubiKey.

    \b
    SLOT            PIV slot of the key
    """
    session = ctx.obj["session"]
    _ensure_authenticated(ctx, pin, management_key)
    try:
        session.delete_key(slot)
    except ApduError as e:
        if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
            raise CliFail(f"No key stored in slot {slot}.")
        raise


@piv.group("certificates")
def cert():
    """
    Manage certificates.
    """


@cert.command("import")
@click.pass_context
@click_management_key_option
@click_pin_option
@click.option("-p", "--password", help="a password may be needed to decrypt the data")
@click.option(
    "-v",
    "--verify",
    is_flag=True,
    help="verify that the certificate matches the private key in the slot",
)
@click.option(
    "-c", "--compress", is_flag=True, help="compresses the certificate before storing"
)
@click_slot_argument
@click.argument("cert", type=click.File("rb"), metavar="CERTIFICATE")
def import_certificate(
    ctx, management_key, pin, slot, cert, password, verify, compress
):
    """
    Import an X.509 certificate.

    Write a certificate to one of the PIV slots on the YubiKey.

    \b
    SLOT            PIV slot of the certificate
    CERTIFICATE     file containing the certificate (use '-' to use stdin)
    """
    session = ctx.obj["session"]

    data = cert.read()

    while True:
        if password is not None:
            password = password.encode()
        try:
            certs = parse_certificates(data, password)
        except InvalidPasswordError:
            logger.debug("Error parsing certificate", exc_info=True)
            if password is None:
                password = click_prompt(
                    "Enter password to decrypt certificate",
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

    if len(certs) > 1:
        #  If multiple certs, only import leaf.
        #  Leaf is the cert with a subject that is not an issuer in the chain.
        leafs = get_leaf_certificates(certs)
        cert_to_import = leafs[0]
    else:
        cert_to_import = certs[0]

    _ensure_authenticated(ctx, pin, management_key)

    if verify:
        public_key = cert_to_import.public_key()

        try:
            metadata = session.get_slot_metadata(slot)
            if metadata.pin_policy in (PIN_POLICY.ALWAYS, PIN_POLICY.ONCE):
                pivman = ctx.obj["pivman_data"]
                _verify_pin(ctx, session, pivman, pin)

            if metadata.touch_policy in (TOUCH_POLICY.ALWAYS, TOUCH_POLICY.CACHED):
                timeout = 0.0
            else:
                timeout = None
        except ApduError as e:
            if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
                raise CliFail(f"No private key in slot {slot}")
            raise
        except NotSupportedError:
            timeout = 1.0

        def do_verify():
            with prompt_timeout(timeout=timeout):
                if not check_key(session, slot, public_key):
                    raise CliFail(
                        "The public key of the certificate does not match the "
                        f"private key in slot {slot}"
                    )

        _verify_pin_if_needed(ctx, session, do_verify, pin)

    session.put_certificate(slot, cert_to_import, compress)
    session.put_object(OBJECT_ID.CHUID, generate_chuid())


@cert.command("export")
@click.pass_context
@click_format_option
@click_slot_argument
@click.argument("certificate", type=click.File("wb"), metavar="CERTIFICATE")
def export_certificate(ctx, format, slot, certificate):
    """
    Export an X.509 certificate.

    Reads a certificate from one of the PIV slots on the YubiKey.

    \b
    SLOT            PIV slot of the certificate
    CERTIFICATE     file to write certificate to (use '-' to use stdout)
    """
    session = ctx.obj["session"]
    try:
        cert = session.get_certificate(slot)
        certificate.write(cert.public_bytes(encoding=format))
        logger.info(f"Certificate from slot {slot} exported to {_fname(certificate)}")
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            raise CliFail("No certificate found.")
        else:
            raise CliFail("Failed reading certificate.")


@cert.command("generate")
@click.pass_context
@click_management_key_option
@click_pin_option
@click_slot_argument
@click.argument("public-key", type=click.File("rb"), metavar="PUBLIC-KEY")
@click.option(
    "-s",
    "--subject",
    help="subject for the certificate, as an RFC 4514 string",
    required=True,
)
@click.option(
    "-d",
    "--valid-days",
    help="number of days until the certificate expires",
    type=click.INT,
    default=365,
    show_default=True,
)
@click_hash_option
def generate_certificate(
    ctx, management_key, pin, slot, public_key, subject, valid_days, hash_algorithm
):
    """
    Generate a self-signed X.509 certificate.

    A self-signed certificate is generated and written to one of the slots on
    the YubiKey. A private key must already be present in the corresponding key slot.

    \b
    SLOT            PIV slot of the certificate
    PUBLIC-KEY      file containing a public key (use '-' to use stdin)
    """
    session = ctx.obj["session"]

    try:
        metadata = session.get_slot_metadata(slot)
        if metadata.touch_policy in (TOUCH_POLICY.ALWAYS, TOUCH_POLICY.CACHED):
            timeout = 0.0
        else:
            timeout = None
    except ApduError as e:
        if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
            raise CliFail(f"No private key in slot {slot}.")
        raise
    except NotSupportedError:
        timeout = 1.0

    data = public_key.read()
    public_key = serialization.load_pem_public_key(data, default_backend())

    now = datetime.datetime.now(datetime.timezone.utc)
    valid_to = now + datetime.timedelta(days=valid_days)

    if "=" not in subject:
        # Old style, common name only.
        subject = "CN=" + subject

    # This verifies PIN, make sure next action is sign
    _ensure_authenticated(ctx, pin, management_key, require_pin_and_key=True)

    try:
        with prompt_timeout(timeout=timeout):
            cert = generate_self_signed_certificate(
                session, slot, public_key, subject, now, valid_to, hash_algorithm
            )
        session.put_certificate(slot, cert)
        session.put_object(OBJECT_ID.CHUID, generate_chuid())
    except ApduError:
        raise CliFail("Certificate generation failed.")


@cert.command("request")
@click.pass_context
@click_pin_option
@click_slot_argument
@click.argument("public-key", type=click.File("rb"), metavar="PUBLIC-KEY")
@click.argument("csr-output", type=click.File("wb"), metavar="CSR")
@click.option(
    "-s",
    "--subject",
    help="subject for the requested certificate, as an RFC 4514 string",
    required=True,
)
@click_hash_option
def generate_certificate_signing_request(
    ctx, pin, slot, public_key, csr_output, subject, hash_algorithm
):
    """
    Generate a Certificate Signing Request (CSR).

    A private key must already be present in the corresponding key slot.

    \b
    SLOT        PIV slot of the certificate
    PUBLIC-KEY  file containing a public key (use '-' to use stdin)
    CSR         file to write CSR to (use '-' to use stdout)
    """
    session = ctx.obj["session"]
    pivman = ctx.obj["pivman_data"]

    data = public_key.read()
    public_key = serialization.load_pem_public_key(data, default_backend())

    if "=" not in subject:
        # Old style, common name only.
        subject = "CN=" + subject

    try:
        metadata = session.get_slot_metadata(slot)
        if metadata.touch_policy in (TOUCH_POLICY.ALWAYS, TOUCH_POLICY.CACHED):
            timeout = 0.0
        else:
            timeout = None
    except ApduError as e:
        if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
            raise CliFail(f"No private key in slot {slot}.")
        raise
    except NotSupportedError:
        timeout = 1.0

    # This verifies PIN, make sure next action is sign
    _verify_pin(ctx, session, pivman, pin)

    try:
        with prompt_timeout(timeout=timeout):
            csr = generate_csr(session, slot, public_key, subject, hash_algorithm)
    except ApduError:
        raise CliFail("Certificate Signing Request generation failed.")

    csr_output.write(csr.public_bytes(encoding=serialization.Encoding.PEM))
    logger.info(f"CSR for slot {slot} written to {_fname(csr_output)}")


@cert.command("delete")
@click.pass_context
@click_management_key_option
@click_pin_option
@click_slot_argument
def delete_certificate(ctx, management_key, pin, slot):
    """
    Delete a certificate.

    Delete a certificate from a PIV slot on the YubiKey.

    \b
    SLOT            PIV slot of the certificate
    """
    session = ctx.obj["session"]
    _ensure_authenticated(ctx, pin, management_key)
    session.delete_certificate(slot)
    session.put_object(OBJECT_ID.CHUID, generate_chuid())


@piv.group("objects")
def objects():
    """
    Manage PIV data objects.

    Examples:

    \b
      Write the contents of a file to data object with ID: abc123:
      $ ykman piv objects import abc123 myfile.txt

    \b
      Read the contents of the data object with ID: abc123 into a file:
      $ ykman piv objects export abc123 myfile.txt

    \b
      Generate a random value for CHUID:
      $ ykman piv objects generate chuid
    """


@objects.command("export")
@click_pin_option
@click.pass_context
@click_object_argument
@click.argument("output", type=click.File("wb"), metavar="OUTPUT")
def read_object(ctx, pin, object_id, output):
    """
    Export an arbitrary PIV data object.

    \b
    OBJECT          name of PIV data object, or ID in HEX
    OUTPUT          file to write object to (use '-' to use stdout)
    """

    session = ctx.obj["session"]
    pivman = ctx.obj["pivman_data"]
    if ctx.obj["fips_unready"] and object_id in (
        OBJECT_ID.PRINTED,
        OBJECT_ID.FINGERPRINTS,
        OBJECT_ID.FACIAL,
        OBJECT_ID.IRIS,
    ):
        raise CliFail(
            "YubiKey FIPS must be in FIPS approved mode to export this object."
        )

    def do_read_object(retry=True):
        try:
            output.write(session.get_object(object_id))
            logger.info(f"Exported object {object_id} to {_fname(output)}")
        except ApduError as e:
            if e.sw == SW.FILE_NOT_FOUND:
                raise CliFail("No data found.")
            elif e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED and retry:
                _verify_pin(ctx, session, pivman, pin)
                do_read_object(retry=False)
            else:
                raise

    do_read_object()


@objects.command("import")
@click_pin_option
@click_management_key_option
@click.pass_context
@click_object_argument
@click.argument("data", type=click.File("rb"), metavar="DATA")
def write_object(ctx, pin, management_key, object_id, data):
    """
    Write an arbitrary PIV object.

    Write a PIV object by providing the object id.
    Yubico writable PIV objects are available in
    the range 5f0000 - 5fffff.

    \b
    OBJECT         name of PIV data object, or ID in HEX
    DATA           file containing the data to be written (use '-' to use stdin)
    """

    session = ctx.obj["session"]
    _ensure_authenticated(ctx, pin, management_key)

    try:
        session.put_object(object_id, data.read())
    except ApduError as e:
        if e.sw == SW.INCORRECT_PARAMETERS:
            raise CliFail("Something went wrong, is the object id valid?")
        raise CliFail("Error writing object.")


@objects.command("generate")
@click_pin_option
@click_management_key_option
@click.pass_context
@click_object_argument
def generate_object(ctx, pin, management_key, object_id):
    """
    Generate and write data for a supported data object.

    \b
    Supported data objects:
      "CHUID" (Card Holder Unique ID)
      "CCC"   (Card Capability Container)

    \b
    OBJECT         name of PIV data object, or ID in HEX
    """

    session = ctx.obj["session"]
    _ensure_authenticated(ctx, pin, management_key)
    if OBJECT_ID.CHUID == object_id:
        session.put_object(OBJECT_ID.CHUID, generate_chuid())
    elif OBJECT_ID.CAPABILITY == object_id:
        session.put_object(OBJECT_ID.CAPABILITY, generate_ccc())
    else:
        raise CliFail("Unsupported object ID for generate.")


def _prompt_management_key(prompt="Enter a management key [blank to use default key]"):
    management_key = click_prompt(
        prompt, default="", hide_input=True, show_default=False
    )
    if management_key == "":
        return DEFAULT_MANAGEMENT_KEY
    try:
        return bytes.fromhex(management_key)
    except Exception:
        raise CliFail("Management key has the wrong format.")


def _prompt_pin(prompt="Enter PIN"):
    return click_prompt(prompt, default="", hide_input=True, show_default=False)


def _ensure_authenticated(
    ctx,
    pin=None,
    management_key=None,
    require_pin_and_key=False,
    mgm_key_prompt=None,
    no_prompt=False,
):
    session = ctx.obj["session"]
    pivman = ctx.obj["pivman_data"]

    if pivman.has_protected_key and not management_key:
        _verify_pin(ctx, session, pivman, pin, no_prompt=no_prompt)
        return True

    _authenticate(ctx, session, management_key, mgm_key_prompt, no_prompt=no_prompt)

    if require_pin_and_key:
        # Ensure verify was the last thing we did
        _verify_pin(ctx, session, pivman, pin, no_prompt=no_prompt)
        return True


def _verify_pin(ctx, session, pivman, pin, no_prompt=False):
    if not pin:
        if no_prompt:
            raise CliFail("PIN required.")
        else:
            pin = _prompt_pin()

    try:
        session.verify_pin(pin)
        if pivman.has_derived_key:
            with prompt_timeout():
                session.authenticate(
                    MANAGEMENT_KEY_TYPE.TDES, derive_management_key(pin, pivman.salt)
                )
            session.verify_pin(pin)  # Ensure verify was the last thing we did
        elif pivman.has_stored_key:
            pivman_prot = get_pivman_protected_data(session)
            try:
                key_type = session.get_management_key_metadata().key_type
            except NotSupportedError:
                key_type = MANAGEMENT_KEY_TYPE.TDES
            with prompt_timeout():
                session.authenticate(key_type, pivman_prot.key)
            session.verify_pin(pin)  # Ensure verify was the last thing we did
    except InvalidPinError as e:
        attempts = e.attempts_remaining
        if attempts > 0:
            raise CliFail(f"PIN verification failed, {attempts} tries left.")
        else:
            raise CliFail("PIN is blocked.")
    except Exception:
        raise CliFail("PIN verification failed.")


def _verify_pin_if_needed(ctx, session, func, pin=None, no_prompt=False):
    try:
        return func()
    except ApduError as e:
        if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
            logger.debug("Command failed due to PIN required, verifying and retrying")
            pivman = ctx.obj["pivman_data"]
            _verify_pin(ctx, session, pivman, pin, no_prompt)
        else:
            raise
    return func()


def _authenticate(ctx, session, management_key, mgm_key_prompt, no_prompt=False):
    if not management_key:
        if no_prompt:
            raise CliFail("Management key required.")
        else:
            if mgm_key_prompt is None:
                management_key = _prompt_management_key()
            else:
                management_key = _prompt_management_key(mgm_key_prompt)
    try:
        try:
            key_type = session.get_management_key_metadata().key_type
        except NotSupportedError:
            key_type = MANAGEMENT_KEY_TYPE.TDES

        with prompt_timeout():
            session.authenticate(key_type, management_key)
    except Exception:
        raise CliFail("Authentication with management key failed.")


def _check_key_support_fips(ctx, key_type, pin_policy):
    info = ctx.obj["info"]
    if CAPABILITY.PIV in info.fips_capable:
        if key_type in (KEY_TYPE.RSA1024, KEY_TYPE.X25519):
            raise CliFail(f"Key type {key_type.name} not supported on YubiKey FIPS")
        if pin_policy in (PIN_POLICY.NEVER,):
            raise CliFail(f"PIN policy {pin_policy.name} not supported on YubiKey FIPS")
