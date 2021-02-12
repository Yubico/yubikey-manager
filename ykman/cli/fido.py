# Copyright (c) 2018 Yubico AB
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

from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2 import (
    Ctap2,
    ClientPin,
    CredentialManagement,
    FPBioEnrollment,
    CaptureError,
)
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SW
from time import sleep
from .util import (
    click_postpone_execution,
    click_prompt,
    click_force_option,
    ykman_group,
    prompt_timeout,
)
from ..fido import is_in_fips_mode, fips_reset, fips_change_pin, fips_verify_pin
from ..hid import list_ctap_devices
from ..device import is_fips_version

import click
import logging

logger = logging.getLogger(__name__)


FIPS_PIN_MIN_LENGTH = 6
PIN_MIN_LENGTH = 4


@ykman_group(FidoConnection)
@click.pass_context
@click_postpone_execution
def fido(ctx):
    """
    Manage the FIDO applications.

    Examples:

    \b
      Reset the FIDO (FIDO2 and U2F) applications:
      $ ykman fido reset

    \b
      Change the FIDO2 PIN from 123456 to 654321:
      $ ykman fido access change-pin --pin 123456 --new-pin 654321

    """
    conn = ctx.obj["conn"]
    try:
        ctx.obj["ctap2"] = Ctap2(conn)
    except (ValueError, CtapError) as e:
        logger.debug("FIDO device does not support CTAP2: %s", e)


@fido.command()
@click.pass_context
def info(ctx):
    """
    Display status of FIDO2 application.
    """
    conn = ctx.obj["conn"]
    ctap2 = ctx.obj.get("ctap2")

    if is_fips_version(ctx.obj["info"].version):
        click.echo(
            "FIPS Approved Mode: {}".format("Yes" if is_in_fips_mode(conn) else "No")
        )
    elif ctap2:
        if ctap2.info.options.get("clientPin"):
            client_pin = ClientPin(ctap2)
            try:
                click.echo(
                    "PIN is set, with {} tries left.".format(
                        client_pin.get_pin_retries()[0]
                    )
                )
            except CtapError as e:
                if e.code == CtapError.ERR.PIN_BLOCKED:
                    click.echo("PIN is blocked.")
                else:
                    raise
        else:
            click.echo("PIN is not set.")
    else:
        click.echo("PIN is not supported.")


@fido.command("reset")
@click_force_option
@click.pass_context
def reset(ctx, force):
    """
    Reset all FIDO applications.

    This action will wipe all FIDO credentials, including FIDO U2F credentials,
    on the YubiKey and remove the PIN code.

    The reset must be triggered immediately after the YubiKey is
    inserted, and requires a touch on the YubiKey.
    """

    n_keys = len(list_ctap_devices())
    if n_keys > 1:
        ctx.fail("Only one YubiKey can be connected to perform a reset.")

    is_fips = is_fips_version(ctx.obj["info"].version)

    if not force:
        if not click.confirm(
            "WARNING! This will delete all FIDO credentials, including FIDO U2F "
            "credentials, and restore factory settings. Proceed?",
            err=True,
        ):
            ctx.abort()

    def prompt_re_insert_key():
        click.echo("Remove and re-insert your YubiKey to perform the reset...")

        removed = False
        while True:
            sleep(0.5)
            keys = list_ctap_devices()
            if not keys:
                removed = True
            if removed and len(keys) == 1:
                return keys[0]

    def try_reset():
        if not force:
            dev = prompt_re_insert_key()
            conn = dev.open_connection(FidoConnection)
        with prompt_timeout():
            if is_fips:
                fips_reset(conn)
            else:
                Ctap2(conn).reset()

    if is_fips:
        if not force:
            destroy_input = click_prompt(
                "WARNING! This is a YubiKey FIPS device. This command will also "
                "overwrite the U2F attestation key; this action cannot be undone and "
                "this YubiKey will no longer be a FIPS compliant device.\n"
                'To proceed, please enter the text "OVERWRITE"',
                default="",
                show_default=False,
            )
            if destroy_input != "OVERWRITE":
                ctx.fail("Reset aborted by user.")

        try:
            try_reset()

        except ApduError as e:
            logger.error("Reset failed", exc_info=e)
            if e.code == SW.COMMAND_NOT_ALLOWED:
                ctx.fail(
                    "Reset failed. Reset must be triggered within 5 seconds after the "
                    "YubiKey is inserted."
                )
            else:
                ctx.fail("Reset failed.")

        except Exception as e:
            logger.error("Reset failed", exc_info=e)
            ctx.fail("Reset failed.")

    else:
        try:
            try_reset()
        except CtapError as e:
            logger.error(e)
            if e.code == CtapError.ERR.ACTION_TIMEOUT:
                ctx.fail(
                    "Reset failed. You need to touch your YubiKey to confirm the reset."
                )
            elif e.code == CtapError.ERR.NOT_ALLOWED:
                ctx.fail(
                    "Reset failed. Reset must be triggered within 5 seconds after the "
                    "YubiKey is inserted."
                )
            else:
                ctx.fail("Reset failed: %s" % e.code.name)
        except Exception as e:
            logger.error(e)
            ctx.fail("Reset failed.")


@fido.group("access")
def access():
    """
    Manage the PIN for FIDO.
    """


@access.command("change-pin")
@click.pass_context
@click.option("-P", "--pin", help="Current PIN code.")
@click.option("-n", "--new-pin", help="A new PIN.")
@click.option(
    "-u", "--u2f", is_flag=True, help="Set FIDO U2F PIN instead of FIDO2 PIN."
)
def change_pin(ctx, pin, new_pin, u2f):
    """
    Set or change the PIN code.

    The FIDO2 PIN must be at least 4 characters long, and supports any type
    of alphanumeric characters.

    On YubiKey FIPS, a PIN can be set for FIDO U2F. That PIN must be at least
    6 characters long.
    """

    is_fips = is_fips_version(ctx.obj["info"].version)

    if is_fips and not u2f:
        ctx.fail("This is a YubiKey FIPS. To set the U2F PIN, pass the --u2f option.")

    if u2f and not is_fips:
        ctx.fail(
            "This is not a YubiKey FIPS, and therefore does not support a U2F PIN. "
            "To set the FIDO2 PIN, remove the --u2f option."
        )

    if is_fips:
        conn = ctx.obj["conn"]
    else:
        ctap2 = ctx.obj.get("ctap2")
        client_pin = ClientPin(ctap2)

    def prompt_new_pin():
        return click_prompt(
            "Enter your new PIN",
            default="",
            hide_input=True,
            show_default=False,
            confirmation_prompt=True,
        )

    def change_pin(pin, new_pin):
        if pin is not None:
            _fail_if_not_valid_pin(ctx, pin, is_fips)
        _fail_if_not_valid_pin(ctx, new_pin, is_fips)
        try:
            if is_fips:
                try:
                    # Failing this with empty current PIN does not cost a retry
                    fips_change_pin(conn, pin or "", new_pin)
                except ApduError as e:
                    if e.code == SW.WRONG_LENGTH:
                        pin = _prompt_current_pin()
                        _fail_if_not_valid_pin(ctx, pin, is_fips)
                        fips_change_pin(conn, pin, new_pin)
                    else:
                        raise

            else:
                client_pin.change_pin(pin, new_pin)

        except CtapError as e:
            logger.error("Failed to change PIN", exc_info=e)
            if e.code == CtapError.ERR.PIN_INVALID:
                ctx.fail("Wrong PIN.")
            elif e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                ctx.fail(
                    "PIN authentication is currently blocked. "
                    "Remove and re-insert the YubiKey."
                )
            elif e.code == CtapError.ERR.PIN_BLOCKED:
                ctx.fail("PIN is blocked.")
            elif e.code == CtapError.ERR.PIN_POLICY_VIOLATION:
                ctx.fail("New PIN is too long.")
            else:
                ctx.fail("Failed to change PIN: %s" % e.code.name)

        except ApduError as e:
            logger.error("Failed to change PIN", exc_info=e)
            if e.code == SW.VERIFY_FAIL_NO_RETRY:
                ctx.fail("Wrong PIN.")
            elif e.code == SW.AUTH_METHOD_BLOCKED:
                ctx.fail("PIN is blocked.")
            else:
                ctx.fail("Failed to change PIN: SW=%04x" % e.code)

    def set_pin(new_pin):
        _fail_if_not_valid_pin(ctx, new_pin, is_fips)
        try:
            client_pin.set_pin(new_pin)
        except CtapError as e:
            logger.error("Failed to set PIN", exc_info=e)
            if e.code == CtapError.ERR.PIN_POLICY_VIOLATION:
                ctx.fail("PIN is too long.")
            else:
                ctx.fail("Failed to set PIN: %s" % e.code.name)

    if not is_fips:
        if ctap2.info.options.get("clientPin"):
            if not pin:
                pin = _prompt_current_pin()
        else:
            if pin:
                ctx.fail("There is no current PIN set. Use --new-pin to set one.")

    if not new_pin:
        new_pin = prompt_new_pin()

    if is_fips or ctap2.info.options.get("clientPin"):
        change_pin(pin, new_pin)
    else:
        set_pin(new_pin)


@access.command("unlock")
@click.pass_context
@click.option("-P", "--pin", help="Current PIN code.")
def unlock(ctx, pin):
    """
    Verify U2F PIN for YubiKey FIPS.

    Unlock the YubiKey FIPS and allow U2F registration.
    """

    conn = ctx.obj["conn"]
    if not is_fips_version(ctx.obj["info"].version):
        ctx.fail(
            "This is not a YubiKey FIPS, and therefore does not support a U2F PIN."
        )

    if pin is None:
        pin = _prompt_current_pin("Enter your PIN")

    _fail_if_not_valid_pin(ctx, pin, True)
    try:
        fips_verify_pin(conn, pin)
    except ApduError as e:
        logger.error("PIN verification failed", exc_info=e)
        if e.code == SW.VERIFY_FAIL_NO_RETRY:
            ctx.fail("Wrong PIN.")
        elif e.code == SW.AUTH_METHOD_BLOCKED:
            ctx.fail("PIN is blocked.")
        elif e.code == SW.COMMAND_NOT_ALLOWED:
            ctx.fail("PIN is not set.")
        else:
            ctx.fail("PIN verification failed: %s" % e.code.name)


def _prompt_current_pin(prompt="Enter your current PIN"):
    return click_prompt(prompt, default="", hide_input=True, show_default=False)


def _fail_if_not_valid_pin(ctx, pin=None, is_fips=False):
    min_length = FIPS_PIN_MIN_LENGTH if is_fips else PIN_MIN_LENGTH
    if not pin or len(pin) < min_length:
        ctx.fail("PIN must be over {} characters long".format(min_length))


def _gen_creds(credman):
    for rp in credman.enumerate_rps():
        for cred in credman.enumerate_creds(rp[CredentialManagement.RESULT.RP_ID_HASH]):
            yield (
                rp[CredentialManagement.RESULT.RP]["id"],
                cred[CredentialManagement.RESULT.CREDENTIAL_ID],
                cred[CredentialManagement.RESULT.USER]["id"],
                cred[CredentialManagement.RESULT.USER]["name"],
            )


def _format_cred(rp_id, user_id, user_name):
    return "{} {} {}".format(rp_id, user_id.hex(), user_name)


@fido.group("credentials")
def creds():
    """
    Manage resident (discoverable) credentials.

    This command lets you manage credentials stored on your YubiKey.
    Credential management is only available when a FIDO PIN is set on the YubiKey.

    \b
    Examples:

    \b
      List stored credentials (providing PIN via argument):
      $ ykman fido credentials list --pin 123456

    \b
      Delete a stored credential by user name (PIN will be prompted for):
      $ ykman fido credentials delete example_user
    """


def _init_credman(ctx, pin):
    ctap2 = ctx.obj.get("ctap2")

    if not ctap2:
        ctx.fail("Managing stored credentials not supported.")
    elif not ctap2.info.options.get("clientPin"):
        ctx.fail("Managing credentials requires having a PIN. Set a PIN first.")

    if pin is None:
        pin = _prompt_current_pin(prompt="Enter your PIN")

    client_pin = ClientPin(ctap2)
    try:
        token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    except CtapError as e:
        if e.code == CtapError.ERR.PIN_INVALID:
            ctx.fail("Wrong PIN.")
        else:
            raise

    return CredentialManagement(ctap2, client_pin.protocol, token)


@creds.command("list")
@click.pass_context
@click.option("-P", "--pin", help="PIN code.")
def creds_list(ctx, pin):
    """
    List resident credentials.
    """
    creds = _init_credman(ctx, pin)
    for (rp_id, _, user_id, user_name) in _gen_creds(creds):
        click.echo(_format_cred(rp_id, user_id, user_name))


@creds.command("delete")
@click.pass_context
@click.argument("query")
@click.option("-P", "--pin", help="PIN code.")
@click.option("-f", "--force", is_flag=True, help="Confirm deletion without prompting")
def creds_delete(ctx, query, pin, force):
    """
    Delete a resident credential.

    \b
    QUERY       A unique substring match of a credentials RP ID, user ID (hex) or name,
                or credential ID.
    """
    credman = _init_credman(ctx, pin)

    hits = [
        (rp_id, cred_id, user_id, user_name)
        for (rp_id, cred_id, user_id, user_name) in _gen_creds(credman)
        if query.lower() in user_name.lower()
        or query.lower() in rp_id.lower()
        or user_id.hex().startswith(query.lower())
        or query.lower() in _format_cred(rp_id, user_id, user_name)
    ]
    if len(hits) == 0:
        ctx.fail("No matches, nothing to be done.")
    elif len(hits) == 1:
        (rp_id, cred_id, user_id, user_name) = hits[0]
        if force or click.confirm(
            "Delete credential {}?".format(_format_cred(rp_id, user_id, user_name))
        ):
            try:
                credman.delete_cred(cred_id)
            except CtapError as e:
                logger.error("Failed to delete resident credential", exc_info=e)
                ctx.fail("Failed to delete resident credential.")
    else:
        ctx.fail("Multiple matches, make the query more specific.")


@fido.group("fingerprints")
def bio():
    """
    Manage fingerprints.

    Requires a YubiKey with fingerprint sensor.
    Fingerprint management is only available when a FIDO PIN is set on the YubiKey.

    \b
    Examples:

    \b
      Register a new fingerprint (providing PIN via argument):
      $ ykman fido fingerprints add "Left thumb" --pin 123456

    \b
      List already stored fingerprints (providing PIN via argument):
      $ ykman fido fingerprints list --pin 123456

    \b
      Delete a stored fingerprint with ID "f691" (PIN will be prompted for):
      $ ykman fido fingerprints delete f691

    """


def _init_bio(ctx, pin):
    ctap2 = ctx.obj.get("ctap2")

    if not ctap2 or "bioEnroll" not in ctap2.info.options:
        ctx.fail("Biometrics is not supported on this YubiKey.")
    elif not ctap2.info.options.get("clientPin"):
        ctx.fail("Biometrics requires having a PIN. Set a PIN first.")

    if pin is None:
        pin = _prompt_current_pin(prompt="Enter your PIN")

    client_pin = ClientPin(ctap2)
    try:
        token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.BIO_ENROLL)
    except CtapError as e:
        if e.code == CtapError.ERR.PIN_INVALID:
            ctx.fail("Wrong PIN.")
        else:
            raise

    return FPBioEnrollment(ctap2, client_pin.protocol, token)


def _format_fp(template_id, name):
    return "{}{}".format(template_id.hex(), " ({})".format(name) if name else "")


@bio.command("list")
@click.pass_context
@click.option("-P", "--pin", help="PIN code.")
def bio_list(ctx, pin):
    """
    List registred fingerprint.

    Lists fingerprints by ID and (if available) label.
    """
    bio = _init_bio(ctx, pin)

    for t_id, name in bio.enumerate_enrollments().items():
        click.echo("ID: {}".format(_format_fp(t_id, name)))


@bio.command("add")
@click.pass_context
@click.argument("name")
@click.option("-P", "--pin", help="PIN code.")
def bio_enroll(ctx, name, pin):
    """
    Add a new fingerprint.

    \b
    NAME        A short readable name for the fingerprint (eg. "Left thumb").
    """
    if len(name.encode()) > 15:
        ctx.fail("Fingerprint name must be a maximum of 15 characters")
    bio = _init_bio(ctx, pin)

    enroller = bio.enroll()
    template_id = None
    while template_id is None:
        click.echo("Press your fingerprint against the sensor now...")
        try:
            template_id = enroller.capture()
            remaining = enroller.remaining
            if remaining:
                click.echo("{} more scans needed.".format(remaining))
        except CaptureError as e:
            click.echo(e)
        except CtapError as e:
            logger.error("Failed to add fingerprint template", exc_info=e)
            ctx.fail("Failed to add fingerprint: %s" % e.code.name)
    click.echo("Capture complete.")
    bio.set_name(template_id, name)


@bio.command("rename")
@click.pass_context
@click.argument("template_id", metavar="ID")
@click.argument("name")
@click.option("-P", "--pin", help="PIN code.")
def bio_rename(ctx, template_id, name, pin):
    """
    Set the label for a fingerprint.

    \b
    ID          The ID of the fingerprint to rename (as shown in "list").
    NAME        A short readable name for the fingerprint (eg. "Left thumb").
    """
    if len(name) >= 16:
        ctx.fail("Fingerprint label must be <= 15 characters.")

    bio = _init_bio(ctx, pin)
    enrollments = bio.enumerate_enrollments()

    key = bytes.fromhex(template_id)
    if key not in enrollments:
        ctx.fail("No fingerprint matching ID={}.".format(template_id))

    bio.set_name(key, name)


@bio.command("delete")
@click.pass_context
@click.argument("template_id", metavar="ID")
@click.option("-P", "--pin", help="PIN code.")
@click.option("-f", "--force", is_flag=True, help="Confirm deletion without prompting")
def bio_delete(ctx, template_id, pin, force):
    """
    Delete a fingerprint.

    Delete a fingerprint from the YubiKey by its ID, which can be seen by running the
    "list" subcommand.
    """
    bio = _init_bio(ctx, pin)
    enrollments = bio.enumerate_enrollments()

    key = bytes.fromhex(template_id)
    if key not in enrollments:
        ctx.fail("No fingerprint matching ID={}".format(template_id))

    name = enrollments[key]
    if force or click.confirm("Delete fingerprint {}?".format(_format_fp(key, name))):
        try:
            bio.remove_enrollment(key)
        except CtapError as e:
            logger.error("Failed to delete fingerprint template", exc_info=e)
            ctx.fail("Failed to delete fingerprint: %s" % e.code.name)
