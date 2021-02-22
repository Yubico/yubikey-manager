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
import click
from ..util import parse_certificates, parse_private_key
from ..openpgp import OpenPgpController, KEY_SLOT, TOUCH_MODE, get_openpgp_info
from .util import (
    cli_fail,
    click_force_option,
    click_format_option,
    click_postpone_execution,
    click_prompt,
    ykman_group,
    EnumChoice,
)

from yubikit.core.smartcard import ApduError, SW, SmartCardConnection

logger = logging.getLogger(__name__)


def one_of(data):
    def inner(ctx, param, key):
        if key is not None:
            return data[key]

    return inner


def get_or_fail(data):
    def inner(key):
        if key in data:
            return data[key]
        raise ValueError(
            f"Invalid value: {key}. Must be one of: {', '.join(data.keys())}"
        )

    return inner


def int_in_range(minval, maxval):
    def inner(val):
        intval = int(val)
        if minval <= intval <= maxval:
            return intval
        raise ValueError(f"Invalid value: {intval}. Must be in range {minval}-{maxval}")

    return inner


@ykman_group(SmartCardConnection)
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
    ctx.obj["controller"] = OpenPgpController(ctx.obj["conn"])


@openpgp.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the OpenPGP application.
    """
    controller = ctx.obj["controller"]
    click.echo(get_openpgp_info(controller))


@openpgp.command()
@click.confirmation_option(
    "-f",
    "--force",
    prompt="WARNING! This will delete "
    "all stored OpenPGP keys and data and restore "
    "factory settings?",
)
@click.pass_context
def reset(ctx):
    """
    Reset all OpenPGP data.

    This action will wipe all OpenPGP data, and set all PINs to their default
    values.
    """
    click.echo("Resetting OpenPGP data, don't remove the YubiKey...")
    ctx.obj["controller"].reset()
    click.echo("Success! All data has been cleared and default PINs are set.")
    echo_default_pins()


def echo_default_pins():
    click.echo("PIN:         123456")
    click.echo("Reset code:  NOT SET")
    click.echo("Admin PIN:   12345678")


@openpgp.group("access")
def access():
    """Manage PIN, Reset Code, and Admin PIN."""


@access.command("set-retries")
@click.argument("pin-retries", type=click.IntRange(1, 99), metavar="PIN-RETRIES")
@click.argument(
    "reset-code-retries", type=click.IntRange(1, 99), metavar="RESET-CODE-RETRIES"
)
@click.argument(
    "admin-pin-retries", type=click.IntRange(1, 99), metavar="ADMIN-PIN-RETRIES"
)
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP.")
@click_force_option
@click.pass_context
def set_pin_retries(
    ctx, admin_pin, pin_retries, reset_code_retries, admin_pin_retries, force
):
    """
    Set PIN, Reset Code and Admin PIN retries.
    """
    controller = ctx.obj["controller"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    resets_pins = controller.version < (4, 0, 0)
    if resets_pins:
        click.echo("WARNING: Setting PIN retries will reset the values for all 3 PINs!")
    if force or click.confirm(
        f"Set PIN retry counters to: {pin_retries} {reset_code_retries} "
        f"{admin_pin_retries}?",
        abort=True,
        err=True,
    ):

        controller.verify_admin(admin_pin)
        controller.set_pin_retries(pin_retries, reset_code_retries, admin_pin_retries)

        if resets_pins:
            click.echo("Default PINs are set.")
            echo_default_pins()


@openpgp.group("keys")
def keys():
    """Manage private keys."""


@keys.command("set-touch")
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_SLOT))
@click.argument("policy", metavar="POLICY", type=EnumChoice(TOUCH_MODE))
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP.")
@click_force_option
@click.pass_context
def set_touch(ctx, key, policy, admin_pin, force):
    """
    Set touch policy for OpenPGP keys.

    \b
    KEY     Key slot to set (sig, enc, aut or att).
    POLICY  Touch policy to set (on, off, fixed, cached or cached-fixed).

    The touch policy is used to require user interaction for all
    operations using the private key on the YubiKey. The touch policy is set
    individually for each key slot. To see the current touch policy, run

    \b
        $ ykman openpgp info

    Touch policies:

    \b
    Off (default)   No touch required
    On              Touch required
    Fixed           Touch required, can't be disabled without a full reset
    Cached          Touch required, cached for 15s after use
    Cached-Fixed    Touch required, cached for 15s after use, can't be disabled
                    without a full reset
    """
    controller = ctx.obj["controller"]

    policy_name = policy.name.lower().replace("_", "-")

    if policy not in controller.supported_touch_policies:
        cli_fail(f"Touch policy {policy_name} not supported by this YubiKey.")

    if key == KEY_SLOT.ATT and not controller.supports_attestation:
        cli_fail("Attestation is not supported by this YubiKey.")

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    if force or click.confirm(
        f"Set touch policy of {key.value.lower()} key to {policy_name}?",
        abort=True,
        err=True,
    ):
        try:
            controller.verify_admin(admin_pin)
            controller.set_touch(key, policy)
        except ApduError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                cli_fail("Touch policy not allowed.")
            logger.debug("Failed to set touch policy", exc_info=e)
            cli_fail("Failed to set touch policy.")


@keys.command("import")
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP.")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_SLOT))
@click.argument("private-key", type=click.File("rb"), metavar="PRIVATE-KEY")
def import_key(ctx, key, private_key, admin_pin):
    """
    Import a private key (ONLY SUPPORTS ATTESTATION KEY).

    Import a private key for OpenPGP attestation.

    \b
    PRIVATE-KEY File containing the private key. Use '-' to use stdin.
    """
    controller = ctx.obj["controller"]

    if key != KEY_SLOT.ATT:
        ctx.fail("Importing keys is only supported for the Attestation slot.")

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)
    try:
        private_key = parse_private_key(private_key.read(), password=None)
    except Exception as e:
        logger.debug("Failed to parse", exc_info=e)
        cli_fail("Failed to parse private key.")
    try:
        controller.verify_admin(admin_pin)
        controller.import_key(key, private_key)
    except Exception as e:
        logger.debug("Failed to import", exc_info=e)
        cli_fail("Failed to import attestation key.")


@keys.command()
@click.pass_context
@click.option("-P", "--pin", help="PIN code.")
@click_format_option
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_SLOT))
@click.argument("certificate", type=click.File("wb"), metavar="CERTIFICATE")
def attest(ctx, key, certificate, pin, format):
    """
    Generate a attestation certificate for a key.

    Attestation is used to show that an asymmetric key was generated on the
    YubiKey and therefore doesn't exist outside the device.

    \b
    KEY         Key slot to attest (sig, enc, aut).
    CERTIFICATE File to write attestation certificate to. Use '-' to use stdout.
    """

    controller = ctx.obj["controller"]

    if not pin:
        pin = click_prompt("Enter PIN", default="", hide_input=True, show_default=False)

    try:
        cert = controller.read_certificate(key)
    except ValueError:
        cert = None

    if not cert or click.confirm(
        f"There is already data stored in the certificate slot for {key.value}, "
        "do you want to overwrite it?"
    ):
        touch_policy = controller.get_touch(KEY_SLOT.ATT)
        if touch_policy in [TOUCH_MODE.ON, TOUCH_MODE.FIXED]:
            click.echo("Touch the YubiKey sensor...")
        try:
            controller.verify_pin(pin)
            cert = controller.attest(key)
            certificate.write(cert.public_bytes(encoding=format))
        except Exception as e:
            logger.debug("Failed to attest", exc_info=e)
            cli_fail("Attestation failed")


@openpgp.group("certificates")
def certificates():
    """
    Manage certificates.
    """


@certificates.command("export")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_SLOT))
@click_format_option
@click.argument("certificate", type=click.File("wb"), metavar="CERTIFICATE")
def export_certificate(ctx, key, format, certificate):
    """
    Export an OpenPGP certificate.

    \b
    KEY         Key slot to read from (sig, enc, aut, or att).
    CERTIFICATE File to write certificate to. Use '-' to use stdout.
    """
    controller = ctx.obj["controller"]
    try:
        cert = controller.read_certificate(key)
    except ValueError:
        cli_fail(f"Failed to read certificate from {key.name}")
    certificate.write(cert.public_bytes(encoding=format))


@certificates.command("delete")
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP.")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_SLOT))
def delete_certificate(ctx, key, admin_pin):
    """
    Delete an OpenPGP certificate.

    \b
    KEY         Key slot to delete certificate from (sig, enc, aut, or att).
    """
    controller = ctx.obj["controller"]
    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)
    try:
        controller.verify_admin(admin_pin)
        controller.delete_certificate(key)
    except Exception as e:
        logger.debug("Failed to delete ", exc_info=e)
        cli_fail("Failed to delete certificate.")


@certificates.command("import")
@click.option("-a", "--admin-pin", help="Admin PIN for OpenPGP.")
@click.pass_context
@click.argument("key", metavar="KEY", type=EnumChoice(KEY_SLOT))
@click.argument("cert", type=click.File("rb"), metavar="CERTIFICATE")
def import_certificate(ctx, key, cert, admin_pin):
    """
    Import an OpenPGP certificate.

    \b
    KEY         Key slot to import certificate to (sig, enc, aut, or att).
    CERTIFICATE File containing the certificate. Use '-' to use stdin.
    """
    controller = ctx.obj["controller"]

    if admin_pin is None:
        admin_pin = click_prompt("Enter Admin PIN", hide_input=True)

    try:
        certs = parse_certificates(cert.read(), password=None)
    except Exception as e:
        logger.debug("Failed to parse", exc_info=e)
        cli_fail("Failed to parse certificate.")
    if len(certs) != 1:
        cli_fail("Can only import one certificate.")
    try:
        controller.verify_admin(admin_pin)
        controller.import_certificate(key, certs[0])
    except Exception as e:
        logger.debug("Failed to import", exc_info=e)
        cli_fail("Failed to import certificate")
