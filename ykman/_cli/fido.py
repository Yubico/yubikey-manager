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

import csv as _csv
import io
import logging
from dataclasses import asdict, replace
from typing import NoReturn, Sequence

import click
from fido2.ctap import STATUS, CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2 import (
    CaptureError,
    ClientPin,
    Config,
    CredentialManagement,
    Ctap2,
    FPBioEnrollment,
)

from yubikit.core import TRANSPORT
from yubikit.core.fido import FidoConnection, SmartCardCtapDevice
from yubikit.core.smartcard import SW, SmartCardConnection
from yubikit.management import CAPABILITY

from ..base import REINSERT_STATUS
from ..fido import (
    fips_change_pin,
    fips_reset,
    fips_verify_pin,
    is_in_fips_mode,
)
from .util import (
    CliFail,
    click_force_option,
    click_group,
    click_postpone_execution,
    click_prompt,
    is_yk4_fips,
    pretty_print,
    prompt_for_touch,
    prompt_timeout,
)

logger = logging.getLogger(__name__)


@click_group(connections=[FidoConnection, SmartCardConnection])
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
    resolve_scp = ctx.obj.get("scp")
    if resolve_scp:
        s_conn = dev.open_connection(SmartCardConnection)
        scp_params = resolve_scp(s_conn)
        conn = SmartCardCtapDevice(s_conn, scp_params)
    else:
        conn = dev.open_connection(FidoConnection)

    ctx.call_on_close(conn.close)
    ctx.obj["conn"] = conn
    info = ctx.obj["info"]

    if CAPABILITY.FIDO2 in info.config.enabled_capabilities[dev.transport]:
        ctx.obj["ctap2"] = Ctap2(conn)
    else:
        supported = CAPABILITY.FIDO2 in info.supported_capabilities[dev.transport]
        logger.debug(f"CTAP2 not enabled, supported: {supported}")

        if ctx.invoked_subcommand == "info":
            return  # Don't fail on info command
        if ctx.invoked_subcommand == "reset" and is_yk4_fips(info):
            # Reset is supported on YK4 FIPS only
            return

        # Fail other commands if CTAP2 is not enabled
        if supported:
            raise CliFail(
                "FIDO2 has been disabled on this YubiKey. "
                "Use 'ykman config' to enable it."
            )
        else:
            raise CliFail("This YubiKey does not support FIDO2.")


@fido.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the FIDO2 application.
    """
    info = ctx.obj["info"]
    ctap2 = ctx.obj.get("ctap2")

    data: dict = {}
    lines: list = [data]

    if CAPABILITY.FIDO2 in info.fips_capable:
        data["FIPS approved"] = CAPABILITY.FIDO2 in info.fips_approved
    elif is_yk4_fips(info):
        data["FIPS approved"] = is_in_fips_mode(ctx.obj["conn"])

    if ctap2:
        if ctap2.info.aaguid:
            data["AAGUID"] = str(ctap2.info.aaguid)
        client_pin = ClientPin(ctap2)  # N.B. All YubiKeys with CTAP2 support PIN.
        if ctap2.info.options["clientPin"]:
            if ctap2.info.force_pin_change:
                lines.append(
                    "NOTE: The FIDO PIN is disabled and must be changed before it can "
                    "be used!"
                )
            pin_retries, power_cycle = client_pin.get_pin_retries()
            if pin_retries:
                data["PIN"] = f"{pin_retries} attempt(s) remaining"
                if power_cycle:
                    lines.append(
                        "PIN is temporarily blocked. "
                        "Remove and re-insert the YubiKey to unblock."
                    )
            else:
                data["PIN"] = "Blocked"
        else:
            data["PIN"] = "Not set"
        data["Minimum PIN length"] = ctap2.info.min_pin_length

        bio_enroll = ctap2.info.options.get("bioEnroll")
        if bio_enroll:
            uv_retries = client_pin.get_uv_retries()
            if uv_retries:
                data["Fingerprints"] = f"Registered, {uv_retries} attempt(s) remaining"
            else:
                data["Fingerprints"] = "Registered, blocked until PIN is verified"
        elif bio_enroll is False:
            data["Fingerprints"] = "Not registered"

        always_uv = ctap2.info.options.get("alwaysUv")
        if always_uv is not None:
            data["Always Require UV"] = "On" if always_uv else "Off"

        remaining_creds = ctap2.info.remaining_disc_creds
        if remaining_creds is not None:
            data["Credential storage remaining"] = remaining_creds

        ep = ctap2.info.options.get("ep")
        if ep is not None:
            data["Enterprise Attestation"] = "Enabled" if ep else "Disabled"
    else:
        dev = ctx.obj["device"]
        supported = CAPABILITY.FIDO2 in info.supported_capabilities[dev.transport]
        data["CTAP2"] = "Disabled" if supported else "Not supported"
        data["PIN"] = "Disabled" if supported else "Not supported"

    click.echo("\n".join(pretty_print(lines)))


def _ctap2_fingerprint(info):
    return asdict(replace(info, enc_identifier=None))


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

    info = ctx.obj["info"]
    if CAPABILITY.FIDO2 in info.reset_blocked:
        raise CliFail(
            "Cannot perform FIDO reset when PIV is configured, "
            "use 'ykman config reset' for full factory reset."
        )

    dev = ctx.obj["device"]
    if CAPABILITY.FIDO2 in info.config.enabled_capabilities[dev.transport]:
        transports = ctx.obj["ctap2"].info.transports_for_reset
        if transports and dev.transport not in transports:
            raise CliFail(
                "Cannot perform FIDO reset on this YubiKey over the current transport. "
                f"Allowed transports: {', '.join(transports)}"
            )

    conn = ctx.obj["conn"]
    if dev.transport == TRANSPORT.NFC:
        is_fips = False
        remove_msg = "Remove your YubiKey from the NFC reader."
        insert_msg = "Place your YubiKey back on the NFC reader now..."

    else:  # USB
        is_fips = is_yk4_fips(info)
        remove_msg = "Remove your YubiKey from the USB port."
        insert_msg = "Re-insert your YubiKey now..."

    if not force:
        click.confirm(
            "WARNING! This will delete all FIDO credentials, including FIDO U2F "
            "credentials, and restore factory settings. Proceed?",
            err=True,
            abort=True,
        )
        if is_fips:
            destroy_input = click_prompt(
                "WARNING! This is a YubiKey FIPS (4 Series) device. This command will "
                "also overwrite the U2F attestation key; this action cannot be undone "
                "and this YubiKey will no longer be a FIPS compliant device.\n"
                'To proceed, enter the text "OVERWRITE"',
                default="",
                show_default=False,
            )
            if destroy_input != "OVERWRITE":
                raise CliFail("Reset aborted by user.")

        conn.close()

        def prompt_reinsert(status):
            match status:
                case REINSERT_STATUS.REMOVE:
                    click.echo(remove_msg)
                case REINSERT_STATUS.REINSERT:
                    click.echo(insert_msg)

        dev.reinsert(reinsert_cb=prompt_reinsert)
        conn = dev.open_connection(type(conn))

    try:
        if is_fips:
            with prompt_timeout():
                fips_reset(conn)
        else:
            ctap2 = Ctap2(conn)
            if info.serial is None:
                # Compare CTAP2 info to ensure we are resetting the same device.
                if _ctap2_fingerprint(ctx.obj["ctap2"].info) != _ctap2_fingerprint(
                    ctap2.info
                ):
                    raise CliFail("Inserted YubiKey does not match the one removed.")
            touch_msg = (
                "Press and hold the YubiKey button for 10 seconds to confirm."
                if ctap2.info.long_touch_for_reset
                else "Touch the YubiKey to confirm."
            )

            def on_keepalive(status):
                if status == STATUS.UPNEEDED:
                    prompt_for_touch(touch_msg)
                elif status == STATUS.PROCESSING:
                    click.echo("Reset in progress, DO NOT REMOVE YOUR YUBIKEY!")

            ctap2.reset(on_keepalive=on_keepalive)
        click.echo("FIDO application data reset.")
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
            raise CliFail(f"Reset failed: {e.code.name}.")
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


def _fail_pin_error(ctx, e, other="%s") -> NoReturn:
    if e.code == CtapError.ERR.PIN_INVALID:
        raise CliFail("Wrong PIN.")
    elif e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
        raise CliFail(
            "PIN authentication is currently blocked. Remove and re-insert the YubiKey."
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
    help="set FIDO U2F PIN instead of FIDO2 PIN (YubiKey FIPS only)",
)
def change_pin(ctx, pin, new_pin, u2f):
    """
    Set or change the PIN code.

    The FIDO2 PIN must be at least 4 characters long, and supports any type of
    alphanumeric characters. Some YubiKeys can be configured to require a longer
    PIN.

    On YubiKey FIPS (4 Series), a PIN can be set for FIDO U2F. That PIN must be at least
    6 characters long.
    """

    info = ctx.obj["info"]
    is_fips = is_yk4_fips(info)

    if is_fips and not u2f:
        raise CliFail(
            "This is a YubiKey FIPS (4 Series). "
            "To set the U2F PIN, pass the --u2f option."
        )

    if u2f and not is_fips:
        raise CliFail(
            "This is not a YubiKey FIPS (4 Series), and therefore does not support a "
            "U2F PIN. To set the FIDO2 PIN, remove the --u2f option."
        )

    if is_fips:
        conn = ctx.obj["conn"]
        min_len = 6
        max_len = 32

        def _fips_change_pin(new_pin):
            fips_pin = pin or ""
            try:
                # Failing this with empty current PIN does not cost a retry
                fips_change_pin(conn, fips_pin, new_pin)
            except ApduError as e:
                if e.code == SW.WRONG_LENGTH:
                    fips_pin = _prompt_current_pin()
                    _fail_if_not_valid_pin(fips_pin)
                    fips_change_pin(conn, fips_pin, new_pin)
                else:
                    raise

        do_change = _fips_change_pin

    else:
        ctap2 = ctx.obj.get("ctap2")
        if not ctap2:
            raise CliFail("PIN is not supported on this YubiKey.")
        client_pin = ClientPin(ctap2)
        min_len = ctap2.info.min_pin_length
        max_len = ctap2.info.max_pin_length
        if (
            info._is_bio
            and CAPABILITY.PIV in info.config.enabled_capabilities[TRANSPORT.USB]
        ):
            max_len = 8
        if ctap2.info.options.get("clientPin"):
            if not pin:
                pin = _prompt_current_pin()

            def _ctap2_change_pin(new_pin):
                client_pin.change_pin(pin, new_pin)

            do_change = _ctap2_change_pin
        else:
            if pin:
                raise CliFail("There is no current PIN set. Use --new-pin to set one.")

            do_change = client_pin.set_pin

    def _fail_if_not_valid_pin(pin=None, name="PIN"):
        if not pin or len(pin) < min_len:
            raise CliFail(f"{name} must be at least {min_len} characters long.")
        if len(pin) > max_len:
            raise CliFail(f"{name} must be at most {max_len} characters long.")

    if not new_pin:
        new_pin = click_prompt(
            "Enter your new PIN",
            hide_input=True,
            confirmation_prompt=True,
        )
    _fail_if_not_valid_pin(new_pin, "New PIN")

    try:
        do_change(new_pin)
    except CtapError as e:
        if e.code == CtapError.ERR.PIN_POLICY_VIOLATION:
            raise CliFail("New PIN doesn't meet complexity requirements.")
        else:
            _fail_pin_error(ctx, e, "Failed to change PIN: %s.")
    except ApduError as e:
        if e.code == SW.VERIFY_FAIL_NO_RETRY:
            raise CliFail("Wrong PIN.")
        elif e.code == SW.AUTH_METHOD_BLOCKED:
            raise CliFail("PIN is blocked.")
        else:
            raise CliFail(f"Failed to change PIN: SW={e.code:04x}.")

    click.echo("FIDO PIN updated.")


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
    For YubiKey FIPS (4 Series) this will unlock the session, allowing U2F registration.
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
            raise CliFail(f"PIN verification failed: {e}.")
    elif is_yk4_fips(ctx.obj["info"]):
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
                raise CliFail(f"PIN verification failed: {e.code:04x}.")
    else:
        raise CliFail("This YubiKey does not support a FIDO PIN.")
    click.echo("PIN verified.")


def _init_config(ctx, pin):
    ctap2 = ctx.obj.get("ctap2")
    if not Config.is_supported(ctap2.info):
        raise CliFail("Authenticator Configuration is not supported on this YubiKey.")

    protocol = None
    token = None
    if ctap2.info.options.get("clientPin"):
        pin = _require_pin(ctx, pin, "Authenticator Configuration")
        client_pin = ClientPin(ctap2)
        try:
            protocol = client_pin.protocol
            token = client_pin.get_pin_token(
                pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG
            )
        except CtapError as e:
            _fail_pin_error(ctx, e, "PIN error: %s.")

    return Config(ctap2, protocol, token)


@access.command("force-change")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
def force_pin_change(ctx, pin):
    """
    Force the PIN to be changed to a new value before use.
    """
    options = ctx.obj["ctap2"].info.options if "ctap2" in ctx.obj else None
    if options is None or not options.get("setMinPINLength"):
        raise CliFail("Force change PIN is not supported on this YubiKey.")
    if not options.get("clientPin"):
        raise CliFail("No PIN is set.")

    config = _init_config(ctx, pin)
    config.set_min_pin_length(force_change_pin=True)
    click.echo("Force PIN change set.")


@access.command("set-min-length")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
@click.option("-R", "--rp-id", multiple=True, help="RP ID to allow")
@click.argument("length", type=click.IntRange(4, 63))
def set_min_pin_length(ctx, pin, rp_id, length):
    """
    Set the minimum length allowed for PIN.

    Optionally use the --rp-id option to specify which RPs are allowed to request this
    information.
    """
    info = ctx.obj["ctap2"].info if "ctap2" in ctx.obj else None
    if info is None or not info.options.get("setMinPINLength"):
        raise CliFail("Set minimum PIN length is not supported on this YubiKey.")
    if info.options.get("alwaysUv") and not info.options.get("clientPin"):
        raise CliFail(
            "Setting min PIN length requires a PIN to be set when alwaysUv is enabled."
        )

    min_len = info.min_pin_length
    if length < min_len:
        raise CliFail(f"Cannot set a minimum length that is shorter than {min_len}.")

    dev_info = ctx.obj["info"]
    if (
        dev_info._is_bio
        and CAPABILITY.PIV in dev_info.config.enabled_capabilities[TRANSPORT.USB]
        and length > 8
    ):
        raise CliFail("Cannot set a minimum length that is longer than 8.")

    config = _init_config(ctx, pin)
    if rp_id:
        ctap2 = ctx.obj.get("ctap2")
        cap = ctap2.info.max_rpids_for_min_pin
        if len(rp_id) > cap:
            raise CliFail(
                f"Authenticator supports up to {cap} RP IDs ({len(rp_id)} given)."
            )

    config.set_min_pin_length(min_pin_length=length, rp_ids=rp_id)
    click.echo("Minimum PIN length set.")


def _prompt_current_pin(prompt="Enter your current PIN"):
    return click_prompt(prompt, hide_input=True)


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


def _format_table(headings: Sequence[str], rows: list[Sequence[str]]) -> str:
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
        _fail_pin_error(ctx, e, "PIN error: %s.")

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
                click.echo("Deleting credential, DO NOT REMOVE YOUR YUBIKEY!")
                credman.delete_cred(cred_id)
                click.echo("Credential deleted.")
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
        _fail_pin_error(ctx, e, "PIN error: %s.")

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
            raise CliFail(f"Failed to add fingerprint: {e.code.name}.")
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
    click.echo("Fingerprint template renamed.")


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
        key: bytes | None = bytes.fromhex(template_id)
    except ValueError:
        key = None

    if not key or key not in enrollments:
        # Match using template_id as NAME
        matches = [k for k in enrollments if enrollments[k] == template_id]
        if len(matches) == 0:
            raise CliFail(f"No fingerprint matching ID={template_id}.")
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
            click.echo("Fingerprint template deleted.")
        except CtapError as e:
            raise CliFail(f"Failed to delete fingerprint: {e.code.name}.")


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
    options = ctx.obj.get("ctap2").info.options if "ctap2" in ctx.obj else None
    if not options or "alwaysUv" not in options:
        raise CliFail("Always Require UV is not supported on this YubiKey.")

    info = ctx.obj["info"]
    if CAPABILITY.FIDO2 in info.fips_capable:
        raise CliFail("Always Require UV can not be disabled on this YubiKey.")

    always_uv = options["alwaysUv"]

    config = _init_config(ctx, pin)
    config.toggle_always_uv()
    click.echo(f"Always Require UV is {'off' if always_uv else 'on'}.")


@config.command("enable-ep-attestation")
@click.pass_context
@click.option("-P", "--pin", help="PIN code")
def enable_ep_attestation(ctx, pin):
    """
    Enables Enterprise Attestation for Authenticators pre-configured to support it.
    """
    options = ctx.obj.get("ctap2").info.options if "ctap2" in ctx.obj else None
    if not options or "ep" not in options:
        raise CliFail("Enterprise Attestation is not supported on this YubiKey.")
    if options.get("alwaysUv") and not options.get("clientPin"):
        raise CliFail(
            "Enabling Enterprise Attestation requires a PIN to be set when alwaysUv is "
            "enabled."
        )

    config = _init_config(ctx, pin)
    config.enable_enterprise_attestation()
    click.echo("Enterprise Attestation enabled.")
