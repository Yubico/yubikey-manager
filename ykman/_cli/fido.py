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
    Config,
)
from fido2.pcsc import CtapPcscDevice
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SW
from time import sleep
from .util import (
    click_postpone_execution,
    click_prompt,
    click_force_option,
    click_group,
    prompt_timeout,
    is_yk4_fips,
    pretty_print,
)
from .util import CliFail
from ..fido import is_in_fips_mode, fips_reset, fips_change_pin, fips_verify_pin
from ..hid import list_ctap_devices
from ..pcsc import list_devices as list_ccid
from smartcard.Exceptions import NoCardException, CardConnectionException
from typing import Optional, Sequence, List, Dict

import io
import csv as _csv
import click
import logging

logger = logging.getLogger(__name__)


FIPS_PIN_MIN_LENGTH = 6
PIN_MIN_LENGTH = 4


@click_group(connections=[FidoConnection])
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
    dev = ctx.obj["device"]
    conn = dev.open_connection(FidoConnection)
    ctx.call_on_close(conn.close)
    ctx.obj["conn"] = conn
    try:
        ctx.obj["ctap2"] = Ctap2(conn)
    except (ValueError, CtapError):
        logger.info("FIDO device does not support CTAP2", exc_info=True)


@fido.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the FIDO2 application.
    """
    conn = ctx.obj["conn"]
    ctap2 = ctx.obj.get("ctap2")
    info: Dict = {}
    lines: List = [info]

    if is_yk4_fips(ctx.obj["info"]):
        info["FIPS Approved Mode"] = "Yes" if is_in_fips_mode(conn) else "No"
    elif ctap2:
        client_pin = ClientPin(ctap2)  # N.B. All YubiKeys with CTAP2 support PIN.
        if ctap2.info.options["clientPin"]:
            if ctap2.info.force_pin_change:
                lines.append(
                    "NOTE: The FIDO PIN is disabled and must be changed before it can "
                    "be used!"
                )
            pin_retries, power_cycle = client_pin.get_pin_retries()
            if pin_retries:
                info["PIN"] = f"{pin_retries} attempt(s) remaining"
                if power_cycle:
                    lines.append(
                        "PIN is temporarily blocked. "
                        "Remove and re-insert the YubiKey to unblock."
                    )
            else:
                info["PIN"] = "blocked"
        else:
            info["PIN"] = "not set"
        info["Minimum PIN length"] = ctap2.info.min_pin_length

        bio_enroll = ctap2.info.options.get("bioEnroll")
        if bio_enroll:
            uv_retries = client_pin.get_uv_retries()
            if uv_retries:
                info["Fingerprints"] = f"registered, {uv_retries} attempt(s) remaining"
            else:
                info["Fingerprints"] = "registered, blocked until PIN is verified"
        elif bio_enroll is False:
            info["Fingerprints"] = "not registered"

        always_uv = ctap2.info.options.get("alwaysUv")
        if always_uv is not None:
            info["Always Require UV"] = "on" if always_uv else "off"

        remaining_creds = ctap2.info.remaining_disc_creds
        if remaining_creds is not None:
            info["Credential storage remaining"] = remaining_creds

        ep = ctap2.info.options.get("ep")
        if ep is not None:
            info["Enterprise Attestation"] = "enabled" if ep else "disabled"

    else:
        info["PIN"] = "not supported"

    click.echo("\n".join(pretty_print(lines)))


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

    conn = ctx.obj["conn"]

    if isinstance(conn, CtapPcscDevice):  # NFC
        readers = list_ccid(conn._name)
        if not readers or readers[0].reader.name != conn._name:
            raise CliFail("Unable to isolate NFC reader.")
        dev = readers[0]
        logger.debug(f"use: {dev}")
        is_fips = False

        def prompt_re_insert():
            click.echo(
                "Remove and re-place your YubiKey on the NFC reader to perform the "
                "reset..."
            )

            removed = False
            while True:
                sleep(0.5)
                try:
                    with dev.open_connection(FidoConnection):
                        if removed:
                            sleep(1.0)  # Wait for the device to settle
                            break
                except CardConnectionException:
                    pass  # Expected, ignore
                except NoCardException:
                    removed = True
            return dev.open_connection(FidoConnection)

    else:  # USB
        n_keys = len(list_ctap_devices())
        if n_keys > 1:
            raise CliFail("Only one YubiKey can be connected to perform a reset.")
        is_fips = is_yk4_fips(ctx.obj["info"])

        ctap2 = ctx.obj.get("ctap2")
        if not is_fips and not ctap2:
            raise CliFail("This YubiKey does not support FIDO reset.")

        def prompt_re_insert():
            click.echo("Remove and re-insert your YubiKey to perform the reset...")

            removed = False
            while True:
                sleep(0.5)
                keys = list_ctap_devices()
                if not keys:
                    removed = True
                if removed and len(keys) == 1:
                    return keys[0].open_connection(FidoConnection)

    if not force:
        click.confirm(
            "WARNING! This will delete all FIDO credentials, including FIDO U2F "
            "credentials, and restore factory settings. Proceed?",
            err=True,
            abort=True,
        )
        if is_fips:
            destroy_input = click_prompt(
                "WARNING! This is a YubiKey FIPS device. This command will also "
                "overwrite the U2F attestation key; this action cannot be undone and "
                "this YubiKey will no longer be a FIPS compliant device.\n"
                'To proceed, please enter the text "OVERWRITE"',
                default="",
                show_default=False,
            )
            if destroy_input != "OVERWRITE":
                raise CliFail("Reset aborted by user.")

        conn = prompt_re_insert()

    try:
        with prompt_timeout():
            if is_fips:
                fips_reset(conn)
            else:
                Ctap2(conn).reset()
        logger.info("FIDO application data reset")
    except CtapError as e:
        if e.code == CtapError.ERR.ACTION_TIMEOUT:
            raise CliFail(
                "Reset failed. You need to touch your YubiKey to confirm the reset."
            )
        elif e.code in (CtapError.ERR.NOT_ALLOWED, CtapError.ERR.PIN_AUTH_BLOCKED):
            raise CliFail(
                "Reset failed. Reset must be triggered within 5 seconds after the "
                "YubiKey is inserted."
            )
        else:
            raise CliFail(f"Reset failed: {e.code.name}")
    except ApduError as e:  # From fips_reset
        if e.code == SW.COMMAND_NOT_ALLOWED:
            raise CliFail(
                "Reset failed. Reset must be triggered within 5 seconds after the "
                "YubiKey is inserted."
            )
        else:
            raise CliFail("Reset failed.")
    except Exception:
        raise CliFail("Reset failed.")


def _fail_pin_error(ctx, e, other="%s"):
    if e.code == CtapError.ERR.PIN_INVALID:
        raise CliFail("Wrong PIN.")
    elif e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
        raise CliFail(
            "PIN authentication is currently blocked. "
            "Remove and re-insert the YubiKey."
        )
    elif e.code == CtapError.ERR.PIN_BLOCKED:
        raise CliFail("PIN is blocked.")
    else:
        raise CliFail(other % e.code)


@fido.group("access")
def access():
    """
    Manage the PIN for FIDO.
    """


@access.command("change-pin")
@click.pass_context
@click.option("-P", "--pin", help="current PIN code")
@click.option("-n", "--new-pin", help="a new PIN")
@click.option(
    "-u",
    "--u2f",
    is_flag=True,
    help="set FIDO U2F PIN instead of FIDO2 PIN (YubiKey 4 FIPS only)",
)
def change_pin(ctx, pin, new_pin, u2f):
    """
    Set or change the PIN code.

    The FIDO2 PIN must be at least 4 characters long, and supports any type
    of alphanumeric characters.

    On YubiKey FIPS, a PIN can be set for FIDO U2F. That PIN must be at least
    6 characters long.
    """

    is_fips = is_yk4_fips(ctx.obj["info"])

    if is_fips and not u2f:
        raise CliFail(
            "This is a YubiKey FIPS. To set the U2F PIN, pass the --u2f option."
        )

    if u2f and not is_fips:
        raise CliFail(
            "This is not a YubiKey 4 FIPS, and therefore does not support a U2F PIN. "
            "To set the FIDO2 PIN, remove the --u2f option."
        )

    if is_fips:
        conn = ctx.obj["conn"]
    else:
        ctap2 = ctx.obj.get("ctap2")
        if not ctap2:
            raise CliFail("PIN is not supported on this YubiKey.")
        client_pin = ClientPin(ctap2)

    def prompt_new_pin():
        return click_prompt(
            "Enter your new PIN",
            hide_input=True,
            confirmation_prompt=True,
        )

    def change_pin(pin, new_pin):
        if pin is not None:
            _fail_if_not_valid_pin(ctx, pin, is_fips)
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
            if e.code == CtapError.ERR.PIN_POLICY_VIOLATION:
                raise CliFail("New PIN doesn't meet policy requirements.")
            else:
                _fail_pin_error(ctx, e, "Failed to change PIN: %s")

        except ApduError as e:
            if e.code == SW.VERIFY_FAIL_NO_RETRY:
                raise CliFail("Wrong PIN.")
            elif e.code == SW.AUTH_METHOD_BLOCKED:
                raise CliFail("PIN is blocked.")
            else:
                raise CliFail(f"Failed to change PIN: SW={e.code:04x}")

    def set_pin(new_pin):
        _fail_if_not_valid_pin(ctx, new_pin, is_fips)
        try:
            client_pin.set_pin(new_pin)
        except CtapError as e:
            if e.code == CtapError.ERR.PIN_POLICY_VIOLATION:
                raise CliFail("New PIN doesn't meet policy requirements.")
            else:
                raise CliFail(f"Failed to set PIN: {e.code}")

    if not is_fips:
        if ctap2.info.options.get("clientPin"):
            if not pin:
                pin = _prompt_current_pin()
        else:
            if pin:
                raise CliFail("There is no current PIN set. Use --new-pin to set one.")

    if not new_pin:
        new_pin = prompt_new_pin()

    if is_fips:
        _fail_if_not_valid_pin(ctx, new_pin, is_fips)
        change_pin(pin, new_pin)
    else:
        min_len = ctap2.info.min_pin_length
        if len(new_pin) < min_len:
            raise CliFail(f"New PIN is too short. Minimum length: {min_len}")
        if ctap2.info.options.get("clientPin"):
            change_pin(pin, new_pin)
        else:
            set_pin(new_pin)
    logger.info("FIDO PIN updated")


def _require_pin(ctx, pin, feature="This feature"):
    ctap2 = ctx.obj.get("ctap2")
    if not ctap2:
        raise CliFail(f"{feature} is not supported on this YubiKey.")
    if not ctap2.info.options.get("clientPin"):
        raise CliFail(f"{feature} requires having a PIN. Set a PIN first.")
    if ctap2.info.force_pin_change:
        raise CliFail("The FIDO PIN is blocked. Change the PIN first.")
    if pin is None:
        pin = _prompt_current_pin(prompt="Enter your PIN")
    return pin


@access.command("verify-pin")
@click.pass_context
@click.option("-P", "--pin", help="current PIN code")
def verify(ctx, pin):
    """
    Verify the FIDO PIN against a YubiKey.

    For YubiKeys supporting FIDO2 this will reset the "retries" counter of the PIN.
    For YubiKey FIPS this will unlock the session, allowing U2F registration.
    """

    ctap2 = ctx.obj.get("ctap2")
    if ctap2:
        pin = _require_pin(ctx, pin)
        client_pin = ClientPin(ctap2)
        try:
            # Get a PIN token to verify the PIN.
            client_pin.get_pin_token(
                pin, ClientPin.PERMISSION.GET_ASSERTION, "ykman.example.com"
            )
        except CtapError as e:
            raise CliFail(f"PIN verification failed: {e}")
    elif is_yk4_fips(ctx.obj["info"]):
        _fail_if_not_valid_pin(ctx, pin, True)
        try:
            fips_verify_pin(ctx.obj["conn"], pin)
        except ApduError as e:
            if e.code == SW.VERIFY_FAIL_NO_RETRY:
                raise CliFail("Wrong PIN.")
            elif e.code == SW.AUTH_METHOD_BLOCKED:
                raise CliFail("PIN is blocked.")
            elif e.code == SW.COMMAND_NOT_ALLOWED:
                raise CliFail("PIN is not set.")
            else:
                raise CliFail(f"PIN verification failed: {e.code.name}")
    else:
        raise CliFail("This YubiKey does not support a FIDO PIN.")
    click.echo("PIN verified.")


def _init_config(ctx, pin):
    ctap2 = ctx.obj.get("ctap2")
    if not Config.is_supported(ctap2.info):
        raise CliFail("Authenticator Configuration is not supported on this YubiKey.")

    pin = _require_pin(ctx, pin, "Authenticator Configuration")
    client_pin = ClientPin(ctap2)
    try:
        token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    except CtapError as e:
        _fail_pin_error(ctx, e, "PIN error: %s")

    return Config(ctap2, client_pin.protocol, token)


@access.command("force-change")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
def force_pin_change(ctx, pin):
    """
    Force the PIN to be changed to a new value before use.
    """
    options = ctx.obj.get("ctap2").info.options
    if not options.get("setMinPINLength"):
        raise CliFail("Force change PIN is not supported on this YubiKey.")

    config = _init_config(ctx, pin)
    config.set_min_pin_length(force_change_pin=True)


@access.command("set-min-length")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
@click.option("-R", "--rp-id", multiple=True, help="RP ID to allow")
@click.argument("length", type=click.IntRange(4))
def set_min_pin_length(ctx, pin, rp_id, length):
    """
    Set the minimum length allowed for PIN.

    Optionally use the --rp option to specify which RPs are allowed to request this
    information.
    """
    options = ctx.obj.get("ctap2").info.options
    if not options.get("setMinPINLength"):
        raise CliFail("Set minimum PIN length is not supported on this YubiKey.")

    config = _init_config(ctx, pin)
    if rp_id:
        ctap2 = ctx.obj.get("ctap2")
        cap = ctap2.info.max_rpids_for_min_pin
        if len(rp_id) > cap:
            raise CliFail(
                f"Authenticator supports up to {cap} RP IDs ({len(rp_id)} given)."
            )
    config.set_min_pin_length(min_pin_length=length, rp_ids=rp_id)


def _prompt_current_pin(prompt="Enter your current PIN"):
    return click_prompt(prompt, hide_input=True)


def _fail_if_not_valid_pin(ctx, pin=None, is_fips=False):
    min_length = FIPS_PIN_MIN_LENGTH if is_fips else PIN_MIN_LENGTH
    if not pin or len(pin) < min_length:
        ctx.fail(f"PIN must be over {min_length} characters long")


def _gen_creds(credman):
    data = credman.get_metadata()
    if data.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT) == 0:
        return  # No credentials
    for rp in credman.enumerate_rps():
        for cred in credman.enumerate_creds(rp[CredentialManagement.RESULT.RP_ID_HASH]):
            yield (
                rp[CredentialManagement.RESULT.RP]["id"],
                cred[CredentialManagement.RESULT.CREDENTIAL_ID],
                cred[CredentialManagement.RESULT.USER]["id"],
                cred[CredentialManagement.RESULT.USER].get("name", ""),
                cred[CredentialManagement.RESULT.USER].get("displayName", ""),
            )


def _format_table(headings: Sequence[str], rows: List[Sequence[str]]) -> str:
    all_rows = [headings] + rows
    padded_rows = [["" for cell in row] for row in all_rows]

    max_cols = max(len(row) for row in all_rows)
    for c in range(max_cols):
        max_width = max(len(row[c]) for row in all_rows if len(row) > c)
        for r in range(len(all_rows)):
            if c < len(all_rows[r]):
                padded_rows[r][c] = all_rows[r][c] + (
                    " " * (max_width - len(all_rows[r][c]))
                )

    return "\n".join("  ".join(row) for row in padded_rows)


def _format_cred(rp_id, user_id, user_name):
    return f"{rp_id} {user_id.hex()} {user_name}"


@fido.group("credentials")
def creds():
    """
    Manage discoverable (resident) credentials.

    This command lets you manage credentials stored on your YubiKey.
    Credential management is only available when a FIDO PIN is set on the YubiKey.

    \b
    Examples:

    \b
      List credentials (providing PIN via argument):
      $ ykman fido credentials list --pin 123456

    \b
      Delete a credential (ID shown in "list" output, PIN will be prompted for):
      $ ykman fido credentials delete da7fdc
    """


def _init_credman(ctx, pin):
    pin = _require_pin(ctx, pin, "Credential Management")

    ctap2 = ctx.obj.get("ctap2")
    client_pin = ClientPin(ctap2)
    try:
        token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    except CtapError as e:
        _fail_pin_error(ctx, e, "PIN error: %s")

    return CredentialManagement(ctap2, client_pin.protocol, token)


@creds.command("list")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
@click.option(
    "-c",
    "--csv",
    is_flag=True,
    help="output full credential information as CSV",
)
def creds_list(ctx, pin, csv):
    """
    List credentials.

    Shows a list of credentials stored on the YubiKey.

    The --csv flag will output more complete information about each credential,
    formatted as a CSV (comma separated values).
    """
    credman = _init_credman(ctx, pin)
    creds = list(_gen_creds(credman))
    if csv:
        buf = io.StringIO()
        writer = _csv.writer(buf)
        writer.writerow(
            ["credential_id", "rp_id", "user_name", "user_display_name", "user_id"]
        )
        writer.writerows(
            [cred_id["id"].hex(), rp_id, user_name, display_name, user_id.hex()]
            for rp_id, cred_id, user_id, user_name, display_name in creds
        )
        click.echo(buf.getvalue())
    else:
        ln = 4
        while len(set(c[1]["id"][:ln] for c in creds)) < len(creds):
            ln += 1
        click.echo(
            _format_table(
                ["Credential ID", "RP ID", "Username", "Display name"],
                [
                    (cred_id["id"][:ln].hex() + "...", rp_id, user_name, display_name)
                    for rp_id, cred_id, _, user_name, display_name in creds
                ],
            )
        )


@creds.command("delete")
@click.pass_context
@click.argument("credential_id")
@click.option("-P", "--pin", help="PIN code")
@click.option("-f", "--force", is_flag=True, help="confirm deletion without prompting")
def creds_delete(ctx, credential_id, pin, force):
    """
    Delete a credential.

    List stored credential IDs using the "list" subcommand.

    \b
    CREDENTIAL_ID       a unique substring match of a Credential ID
    """
    credman = _init_credman(ctx, pin)
    credential_id = credential_id.rstrip(".").lower()

    hits = [
        (rp_id, cred_id, user_name, display_name)
        for (rp_id, cred_id, _, user_name, display_name) in _gen_creds(credman)
        if cred_id["id"].hex().startswith(credential_id)
    ]
    if len(hits) == 0:
        raise CliFail("No matches, nothing to be done.")
    elif len(hits) == 1:
        (rp_id, cred_id, user_name, display_name) = hits[0]
        if force or click.confirm(
            f"Delete {rp_id} {user_name} {display_name} ({cred_id['id'].hex()})?"
        ):
            try:
                credman.delete_cred(cred_id)
                logger.info("Credential deleted")
            except CtapError:
                raise CliFail("Failed to delete credential.")
    else:
        raise CliFail("Multiple matches, make the credential ID more specific.")


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
        raise CliFail("Biometrics is not supported on this YubiKey.")
    pin = _require_pin(ctx, pin, "Biometrics")

    client_pin = ClientPin(ctap2)
    try:
        token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.BIO_ENROLL)
    except CtapError as e:
        _fail_pin_error(ctx, e, "PIN error: %s")

    return FPBioEnrollment(ctap2, client_pin.protocol, token)


def _format_fp(template_id, name):
    return f"{template_id.hex()}{f' ({name})' if name else ''}"


@bio.command("list")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
def bio_list(ctx, pin):
    """
    List registered fingerprints.

    Lists fingerprints by ID and (if available) label.
    """
    bio = _init_bio(ctx, pin)

    for t_id, name in bio.enumerate_enrollments().items():
        click.echo(f"ID: {_format_fp(t_id, name)}")


@bio.command("add")
@click.pass_context
@click.argument("name")
@click.option("-P", "--pin", help="PIN code")
def bio_enroll(ctx, name, pin):
    """
    Add a new fingerprint.

    \b
    NAME        a short readable name for the fingerprint (eg. "Left thumb")
    """
    if len(name.encode()) > 15:
        ctx.fail("Fingerprint name must be a maximum of 15 characters")
    bio = _init_bio(ctx, pin)

    enroller = bio.enroll()
    template_id = None
    while template_id is None:
        click.echo("Place your finger against the sensor now...")
        try:
            template_id = enroller.capture()
            remaining = enroller.remaining
            if remaining:
                click.echo(f"{remaining} more scans needed.")
        except CaptureError as e:
            logger.debug(f"Capture error: {e.code}")
            click.echo("Capture failed. Re-center your finger, and try again.")
        except CtapError as e:
            if e.code == CtapError.ERR.FP_DATABASE_FULL:
                raise CliFail(
                    "Fingerprint storage full. "
                    "Remove some fingerprints before adding new ones."
                )
            elif e.code == CtapError.ERR.USER_ACTION_TIMEOUT:
                raise CliFail("Failed to add fingerprint due to user inactivity.")
            raise CliFail(f"Failed to add fingerprint: {e.code.name}")
    logger.info("Fingerprint template registered")
    click.echo("Capture complete.")
    bio.set_name(template_id, name)
    logger.info("Fingerprint template name set")


@bio.command("rename")
@click.pass_context
@click.argument("template_id", metavar="ID")
@click.argument("name")
@click.option("-P", "--pin", help="PIN code")
def bio_rename(ctx, template_id, name, pin):
    """
    Set the label for a fingerprint.

    \b
    ID          the ID of the fingerprint to rename (as shown in "list")
    NAME        a short readable name for the fingerprint (eg. "Left thumb")
    """
    if len(name.encode()) >= 16:
        ctx.fail("Fingerprint name must be a maximum of 15 bytes")

    bio = _init_bio(ctx, pin)
    enrollments = bio.enumerate_enrollments()

    key = bytes.fromhex(template_id)
    if key not in enrollments:
        raise CliFail(f"No fingerprint matching ID={template_id}.")

    bio.set_name(key, name)
    logger.info("Fingerprint template renamed")


@bio.command("delete")
@click.pass_context
@click.argument("template_id", metavar="ID")
@click.option("-P", "--pin", help="PIN code")
@click.option("-f", "--force", is_flag=True, help="confirm deletion without prompting")
def bio_delete(ctx, template_id, pin, force):
    """
    Delete a fingerprint.

    Delete a fingerprint from the YubiKey by its ID, which can be seen by running the
    "list" subcommand.
    """
    bio = _init_bio(ctx, pin)
    enrollments = bio.enumerate_enrollments()

    try:
        key: Optional[bytes] = bytes.fromhex(template_id)
    except ValueError:
        key = None

    if key not in enrollments:
        # Match using template_id as NAME
        matches = [k for k in enrollments if enrollments[k] == template_id]
        if len(matches) == 0:
            raise CliFail(f"No fingerprint matching ID={template_id}")
        elif len(matches) > 1:
            raise CliFail(
                f"Multiple matches for NAME={template_id}. "
                "Delete by template ID instead."
            )
        key = matches[0]

    name = enrollments[key]
    if force or click.confirm(f"Delete fingerprint {_format_fp(key, name)}?"):
        try:
            bio.remove_enrollment(key)
            logger.info("Fingerprint template deleted")
        except CtapError as e:
            raise CliFail(f"Failed to delete fingerprint: {e.code.name}")


@fido.group("config")
def config():
    """
    Manage FIDO configuration.
    """


@config.command("toggle-always-uv")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
def toggle_always_uv(ctx, pin):
    """
    Toggles the state of Always Require User Verification.
    """
    options = ctx.obj.get("ctap2").info.options
    if "alwaysUv" not in options:
        raise CliFail("Always Require UV is not supported on this YubiKey.")

    config = _init_config(ctx, pin)
    config.toggle_always_uv()


@config.command("enable-ep-attestation")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
def enable_ep_attestation(ctx, pin):
    """
    Enables Enterprise Attestation for Authenticators pre-configured to support it.
    """
    options = ctx.obj.get("ctap2").info.options
    if "ep" not in options:
        raise CliFail("Enterprise Attestation is not supported on this YubiKey.")

    config = _init_config(ctx, pin)
    config.enable_enterprise_attestation()
