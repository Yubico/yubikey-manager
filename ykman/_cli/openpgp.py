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

import logging
from enum import IntEnum

import click

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SW, ApduError, SmartCardConnection
from yubikit.management import CAPABILITY
from yubikit.openpgp import (
    KEY_REF as _KEY_REF,
)
from yubikit.openpgp import (
    KEY_STATUS,
    PIN_POLICY,
    UIF,
    OpenPgpSession,
)

from ..openpgp import get_key_info, get_openpgp_info, safe_reset
from ..util import parse_certificates, parse_private_key
from .util import (
    CliFail,
    EnumChoice,
    click_force_option,
    click_format_option,
    click_group,
    click_postpone_execution,
    click_prompt,
    get_scp_params,
    log_or_echo,
    pretty_print,
)

logger = logging.getLogger(__name__)


class KEY_REF(IntEnum):
    SIG = 0x01
    DEC = 0x02
    AUT = 0x03
    ATT = 0x81
    ENC = 0x02  # Alias for backwards compatibility, will be removed in ykman 6

    def __getattribute__(self, name: str):
        return _KEY_REF(self).__getattribute__(name)


def _fname(fobj):
    return getattr(fobj, "name", fobj)


@click_group(connections=[SmartCardConnection])
@click.pass_context
@click_postpone_execution
def openpgp(ctx):
    """
    Manage the OpenPGP application.

    Examples:

    \b
      Set the retries for PIN, Reset Code and Admin PIN to 10:
      $ ykman openpgp access set-retries 10 10 10

    \b
      Require touch to use the authentication key:
      $ ykman openpgp keys set-touch aut on
    """
    dev = ctx.obj["device"]
    conn = dev.open_connection(SmartCardConnection)
    ctx.call_on_close(conn.close)

    scp_params = get_scp_params(ctx, CAPABILITY.OPENPGP, conn)

    try:
        ctx.obj["session"] = OpenPgpSession(conn, scp_params)
    except ApduError as e:
        if (
            e.sw == SW.CONDITIONS_NOT_SATISFIED
            and not scp_params
            and dev.transport == TRANSPORT.NFC
        ):
            raise CliFail("Unable to manage OpenPGP over NFC without SCP")
        elif e.sw == SW.MEMORY_FAILURE:
            if ctx.invoked_subcommand == "reset":
                ctx.obj["conn"] = conn
            else:
                raise CliFail(
                    "Memory corruption detected, OpenPGP needs to be reset using "
                    "'ykman openpgp reset'"
                )
        else:
            raise


@openpgp.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the OpenPGP application.
    """
    info = ctx.obj["info"]
    data = get_openpgp_info(ctx.obj["session"])
    if CAPABILITY.OPENPGP in info.fips_capable:
        # This is a bit ugly as it makes assumptions about the structure of data
        data["FIPS approved"] = CAPABILITY.OPENPGP in info.fips_approved
    click.echo("\n".join(pretty_print(data)))


@openpgp.command()
@click_force_option
@click.pass_context
def reset(ctx, force):
    """
    Reset all OpenPGP data.

    This action will wipe all OpenPGP data, and set all PINs to their default
    values.

    The attestation key and certificate will NOT be reset.
    """
    if not force:
        click.confirm(
            "WARNING! This will delete all stored OpenPGP keys and data and restore "
            "factory settings. Proceed?",
            abort=True,
            err=True,
        )

    click.echo("Resetting OpenPGP data, don't remove the YubiKey...")
    if "session" in ctx.obj:
        ctx.obj["session"].reset()
    else:
        safe_reset(ctx.obj["conn"])
    logger.info("OpenPGP application data reset")
    click.echo(
        "Reset complete. OpenPGP data has been cleared and default PINs are set."
    )
    echo_default_pins()


def echo_default_pins():
    click.echo("PIN:         123456")
    click.echo("Reset code:  NOT SET")
    click.echo("Admin PIN:   12345678")


@openpgp.group("access")
def access():
    """Manage PIN, Reset Code, and Admin PIN."""


@access.command("set-retries")
@click.argument("user-pin-retries", type=click.IntRange(1, 99), metavar="PIN-RETRIES")
@click.argument(
    "reset-code-retries", type=click.IntRange(1, 99), metavar="RESET-CODE-RETRIES"
)
@click.argument(
    "admin-pin-retries", type=click.IntRange(1, 99), metavar="ADMIN-PIN-RETRIES"
)
@click.option("-a", "--admin-pin", help="admin PIN for OpenPGP")
@click_force_option
@click.pass_context
def set_pin_retries(
    ctx, admin_pin, user_pin_retries, reset_code_retries, admin_pin_retries, force
):
    """
    Set the number of retry attempts for the User PIN, Reset Code, and Admin PIN.
    """
    session = ctx.obj["session"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    resets_pins = session.version < (4, 0, 0)
    if resets_pins:
        click.echo("WARNING: Setting PIN retries will reset the values for all 3 PINs!")
    if force or click.confirm(
        f"Set PIN retry counters to: {user_pin_retries} {reset_code_retries} "
        f"{admin_pin_retries}?",
        abort=True,
        err=True,
    ):
        session.verify_admin(admin_pin)
        session.set_pin_attempts(
            user_pin_retries, reset_code_retries, admin_pin_retries
        )
        click.echo("Number of PIN/Reset Code/Admin PIN retries set.")

        if resets_pins:
            click.echo("Default values have been restored:")
            echo_default_pins()


@access.command("change-pin")
@click.option("-P", "--pin", help="current PIN code")
@click.option("-n", "--new-pin", help="a new PIN")
@click.pass_context
def change_pin(ctx, pin, new_pin):
    """
    Change the User PIN.

    The PIN has a minimum length of 6 (or 8, for YubiKey 5.7+ FIPS when not using KDF),
    and supports any type of alphanumeric characters.
    """

    session = ctx.obj["session"]

    if pin is None:
        pin = click_prompt("Enter PIN", hide_input=True)

    if new_pin is None:
        new_pin = click_prompt(
            "New PIN",
            hide_input=True,
            confirmation_prompt=True,
        )

    try:
        session.change_pin(pin, new_pin)
        click.echo("User PIN has been changed.")
    except ApduError as e:
        if e.sw == SW.CONDITIONS_NOT_SATISFIED:
            raise CliFail("PIN does not meet complexity requirement.")
        raise


@access.command("change-reset-code")
@click.option("-a", "--admin-pin", help="Admin PIN")
@click.option("-r", "--reset-code", help="a new Reset Code")
@click.pass_context
def change_reset_code(ctx, admin_pin, reset_code):
    """
    Change the Reset Code.

    The Reset Code has a minimum length of 6, and supports any type of
    alphanumeric characters.
    """

    session = ctx.obj["session"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    if reset_code is None:
        reset_code = click_prompt(
            "New Reset Code",
            hide_input=True,
            confirmation_prompt=True,
        )

    session.verify_admin(admin_pin)
    try:
        session.set_reset_code(reset_code)
        click.echo("Reset Code has been changed.")
    except ApduError as e:
        if e.sw == SW.CONDITIONS_NOT_SATISFIED:
            raise CliFail("Reset Code does not meet complexity requirement.")
        raise


@access.command("change-admin-pin")
@click.option("-a", "--admin-pin", help="current Admin PIN")
@click.option("-n", "--new-admin-pin", help="new Admin PIN")
@click.pass_context
def change_admin(ctx, admin_pin, new_admin_pin):
    """
    Change the Admin PIN.

    The Admin PIN has a minimum length of 8, and supports any type of
    alphanumeric characters.
    """

    session = ctx.obj["session"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    if new_admin_pin is None:
        new_admin_pin = click_prompt(
            "New Admin PIN",
            hide_input=True,
            confirmation_prompt=True,
        )

    try:
        session.change_admin(admin_pin, new_admin_pin)
        click.echo("Admin PIN has been changed.")
    except ApduError as e:
        if e.sw == SW.CONDITIONS_NOT_SATISFIED:
            raise CliFail("Admin PIN does not meet complexity requirement.")
        raise


@access.command("unblock-pin")
@click.option(
    "-a", "--admin-pin", help='Admin PIN (use "-" as a value to prompt for input)'
)
@click.option("-r", "--reset-code", help="Reset Code")
@click.option("-n", "--new-pin", help="a new PIN")
@click.pass_context
def unblock_pin(ctx, admin_pin, reset_code, new_pin):
    """
    Unblock the PIN (using Reset Code or Admin PIN).

    If the PIN is lost or blocked you can reset it to a new value using the Reset Code.
    Alternatively, the Admin PIN can be used (using the "-a, --admin-pin" option)
    instead of the Reset Code.

    The new PIN has a minimum length of 6, and supports any type of
    alphanumeric characters.
    """

    session = ctx.obj["session"]

    if reset_code is not None and admin_pin is not None:
        raise CliFail(
            "Invalid options: Only one of --reset-code and --admin-pin may be used."
        )

    if admin_pin == "-":
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    if reset_code is None and admin_pin is None:
        reset_code = click_prompt("Enter Reset Code", hide_input=True)

    if new_pin is None:
        new_pin = click_prompt(
            "New PIN",
            hide_input=True,
            confirmation_prompt=True,
        )

    if admin_pin:
        session.verify_admin(admin_pin)

    try:
        session.reset_pin(new_pin, reset_code)
        click.echo("User PIN has been changed.")
    except ApduError as e:
        if e.sw == SW.CONDITIONS_NOT_SATISFIED:
            raise CliFail("New PIN does not meet complexity requirement.")
        raise


@access.command("set-signature-policy")
@click.argument("policy", metavar="POLICY", type=EnumChoice(PIN_POLICY))
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP")
@click.pass_context
def set_signature_policy(ctx, policy, admin_pin):
    """
    Set the Signature PIN policy.

    The Signature PIN policy is used to control whether the PIN is
    always required when using the Signature key, or if it is required
    only once per session.

    \b
    POLICY  signature PIN policy to set (always, once)
    """
    session = ctx.obj["session"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    try:
        session.verify_admin(admin_pin)
        session.set_signature_pin_policy(policy)
        click.echo("Signature PIN policy has been set.")
    except Exception:
        raise CliFail("Failed to set new Signature PIN policy.")


@openpgp.group("keys")
def keys():
    """Manage private keys."""


@keys.command("info")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_REF))
def metadata(ctx, key):
    """
    Show metadata about a private key.

    This will show what type of key is stored in a specific slot,
    whether it was imported into the YubiKey, or generated on-chip,
    and what the Touch policy is for using the key.

    \b
    KEY            key slot to set (sig, dec, aut or att)
    """

    session = ctx.obj["session"]
    discretionary = session.get_application_related_data().discretionary
    status = discretionary.key_information.get(key)
    if status == KEY_STATUS.NONE:
        raise CliFail(f"No key stored in slot {key.name}.")
    info = get_key_info(discretionary, key, status)
    click.echo("\n".join(pretty_print(info)))


@keys.command("set-touch")
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_REF))
@click.argument("policy", metavar="POLICY", type=EnumChoice(UIF))
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP")
@click_force_option
@click.pass_context
def set_touch(ctx, key, policy, admin_pin, force):
    """
    Set the touch policy for OpenPGP keys.

    The touch policy is used to require user interaction for all operations using the
    private key on the YubiKey. The touch policy is set individually for each key slot.
    To see the current touch policy, run the "openpgp info" subcommand.

    WARNING: Setting the touch policy of the attestation key to "fixed" cannot be undone
    without replacing the attestation private key.

    Touch policies:

    \b
    Off (default)  no touch required
    On             touch required
    Fixed          touch required, can't be disabled without deleting the private key
    Cached         touch required, cached for 15s after use
    Cached-Fixed   touch required, cached for 15s after use, can't be disabled
                   without deleting the private key

    \b
    KEY            key slot to set (sig, dec, aut or att)
    POLICY         touch policy to set (on, off, fixed, cached or cached-fixed)
    """
    session = ctx.obj["session"]
    policy_name = policy.name.lower().replace("_", "-")

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    prompt = f"Set touch policy of {key.name} key to {policy_name}?"
    if policy.is_fixed:
        prompt = (
            "WARNING: This touch policy cannot be changed without deleting the "
            + "corresponding key slot!\n"
            + prompt
        )

    if force or click.confirm(prompt, abort=True, err=True):
        try:
            session.verify_admin(admin_pin)
            session.set_uif(key, policy)
            click.echo(f"Touch policy for slot {key.name} set.")
        except ApduError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                raise CliFail("Touch policy not allowed.")
            raise CliFail("Failed to set touch policy.")


@keys.command("import")
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_REF))
@click.argument("private-key", type=click.File("rb"), metavar="PRIVATE-KEY")
def import_key(ctx, key, private_key, admin_pin):
    """
    Import a private key for OpenPGP attestation.

    The attestation key is by default pre-generated during production with a
    Yubico-issued key and certificate.

    WARNING: This private key cannot be recovered once overwritten!

    \b
    KEY          key slot to import to (only 'att' supported)
    PRIVATE-KEY  file containing the private key (use '-' to use stdin)
    """
    session = ctx.obj["session"]

    if key != KEY_REF.ATT:
        ctx.fail("Importing keys is only supported for the Attestation slot.")

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)
    try:
        private_key = parse_private_key(private_key.read(), password=None)
    except Exception:
        raise CliFail("Failed to parse private key.")
    try:
        session.verify_admin(admin_pin)
        session.put_key(key, private_key)
        click.echo(f"Private key imported for slot {key.name}.")
    except Exception:
        raise CliFail("Failed to import attestation key.")


@keys.command()
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
@click_format_option
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_REF, hidden=[KEY_REF.ATT]))
@click.argument("certificate", type=click.File("wb"), metavar="CERTIFICATE")
def attest(ctx, key, certificate, pin, format):
    """
    Generate an attestation certificate for a key.

    Attestation is used to show that an asymmetric key was generated on the
    YubiKey and therefore doesn't exist outside the device.

    \b
    KEY          key slot to attest (sig, dec, aut)
    CERTIFICATE  file to write attestation certificate to (use '-' to use stdout)
    """

    session = ctx.obj["session"]

    if not pin:
        pin = click_prompt("Enter PIN", hide_input=True)

    try:
        cert = session.get_certificate(key)
    except ValueError:
        cert = None

    if not cert or click.confirm(
        f"There is already data stored in the certificate slot for {key.value}, "
        "do you want to overwrite it?"
    ):
        touch_policy = session.get_uif(KEY_REF.ATT)
        if touch_policy in [UIF.ON, UIF.FIXED]:
            click.echo("Touch the YubiKey sensor...")
        try:
            session.verify_pin(pin)
            cert = session.attest_key(key)
            certificate.write(cert.public_bytes(encoding=format))
            log_or_echo(
                f"Attestation certificate for slot {key.name} written to "
                f"{_fname(certificate)}",
                logger,
                certificate,
            )
        except Exception:
            raise CliFail("Attestation failed.")


@openpgp.group("certificates")
def certificates():
    """
    Manage certificates.
    """


@certificates.command("export")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_REF))
@click_format_option
@click.argument("certificate", type=click.File("wb"), metavar="CERTIFICATE")
def export_certificate(ctx, key, format, certificate):
    """
    Export an OpenPGP certificate.

    \b
    KEY          key slot to read from (sig, dec, aut, or att)
    CERTIFICATE  file to write certificate to (use '-' to use stdout)
    """
    session = ctx.obj["session"]

    try:
        cert = session.get_certificate(key)
    except ValueError:
        raise CliFail(f"Failed to read certificate from slot {key.name}.")
    certificate.write(cert.public_bytes(encoding=format))
    log_or_echo(
        f"Certificate for slot {key.name} exported to {_fname(certificate)}",
        logger,
        certificate,
    )


@certificates.command("delete")
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_REF))
def delete_certificate(ctx, key, admin_pin):
    """
    Delete an OpenPGP certificate.

    \b
    KEY  key slot to delete certificate from (sig, dec, aut, or att)
    """
    session = ctx.obj["session"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)
    try:
        session.verify_admin(admin_pin)
        session.delete_certificate(key)
        click.echo(f"Certificate for slot {key.name} deleted.")
    except Exception:
        raise CliFail("Failed to delete certificate.")


@certificates.command("import")
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_REF))
@click.argument("cert", type=click.File("rb"), metavar="CERTIFICATE")
def import_certificate(ctx, key, cert, admin_pin):
    """
    Import an OpenPGP certificate.

    \b
    KEY          key slot to import certificate to (sig, dec, aut, or att)
    CERTIFICATE  file containing the certificate (use '-' to use stdin)
    """
    session = ctx.obj["session"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    try:
        certs = parse_certificates(cert.read(), password=None)
    except Exception:
        raise CliFail("Failed to parse certificate.")
    if len(certs) != 1:
        raise CliFail("Can only import one certificate.")
    try:
        session.verify_admin(admin_pin)
        session.put_certificate(key, certs[0])
        click.echo(f"Certificate imported into slot {key.name}")
    except Exception:
        raise CliFail("Failed to import certificate.")
