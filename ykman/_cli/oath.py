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

import click
import logging
from .util import (
    CliFail,
    click_force_option,
    click_postpone_execution,
    click_callback,
    click_parse_b32_key,
    click_prompt,
    click_group,
    prompt_for_touch,
    prompt_timeout,
    EnumChoice,
    is_yk4_fips,
)
from yubikit.core.smartcard import ApduError, SW, SmartCardConnection
from yubikit.oath import (
    OathSession,
    CredentialData,
    OATH_TYPE,
    HASH_ALGORITHM,
    parse_b32_key,
    _format_cred_id,
)
from ..oath import is_steam, calculate_steam, is_hidden, delete_broken_credential
from ..settings import AppData


logger = logging.getLogger(__name__)


@click_group(connections=[SmartCardConnection])
@click.pass_context
@click_postpone_execution
def oath(ctx):
    """
    Manage the OATH application.

    Examples:

    \b
      Generate codes for accounts starting with 'yubi':
      $ ykman oath accounts code yubi

    \b
      Add an account with the secret key f5up4ub3dw and the name yubico,
      which requires touch:
      $ ykman oath accounts add yubico f5up4ub3dw --touch

    \b
      Set a password for the OATH application:
      $ ykman oath access change-password
    """

    dev = ctx.obj["device"]
    conn = dev.open_connection(SmartCardConnection)
    ctx.call_on_close(conn.close)
    ctx.obj["session"] = OathSession(conn)
    ctx.obj["oath_keys"] = AppData("oath_keys")


@oath.command()
@click.pass_context
def info(ctx):
    """
    Display general status of the OATH application.
    """
    session = ctx.obj["session"]
    version = session.version
    click.echo(f"OATH version: {version[0]}.{version[1]}.{version[2]}")
    click.echo("Password protection: " + ("enabled" if session.locked else "disabled"))

    keys = ctx.obj["oath_keys"]
    if session.locked and session.device_id in keys:
        click.echo("The password for this YubiKey is remembered by ykman.")

    if is_yk4_fips(ctx.obj["info"]):
        click.echo(f"FIPS Approved Mode: {'Yes' if session.locked else 'No'}")


@oath.command()
@click.pass_context
@click_force_option
def reset(ctx, force):
    """
    Reset all OATH data.

    This action will delete all accounts and restore factory settings for
    the OATH application on the YubiKey.
    """

    force or click.confirm(
        "WARNING! This will delete all stored OATH accounts and restore factory "
        "settings. Proceed?",
        abort=True,
        err=True,
    )

    session = ctx.obj["session"]
    click.echo("Resetting OATH data...")
    old_id = session.device_id
    session.reset()

    keys = ctx.obj["oath_keys"]
    if old_id in keys:
        del keys[old_id]
        keys.write()
        logger.info("Deleted remembered access key")

    click.echo("Success! All OATH accounts have been deleted from the YubiKey.")


click_password_option = click.option(
    "-p", "--password", help="the password to unlock the YubiKey"
)


click_remember_option = click.option(
    "-r",
    "--remember",
    is_flag=True,
    help="remember the password on this machine",
)


def _validate(ctx, key, remember):
    session = ctx.obj["session"]
    keys = ctx.obj["oath_keys"]
    session.validate(key)
    if remember:
        keys.put_secret(session.device_id, key.hex())
        keys.write()
        logger.info("Access key remembered")
        click.echo("Password remembered.")


def _init_session(ctx, password, remember, prompt="Enter the password"):
    session = ctx.obj["session"]
    keys = ctx.obj["oath_keys"]
    device_id = session.device_id

    if session.locked:
        try:
            # Use password, if given as argument
            if password:
                logger.debug("Access key required, using provided password")
                key = session.derive_key(password)
                _validate(ctx, key, remember)
                return

            # Use stored key, if available
            if device_id in keys:
                logger.debug("Access key required, using remembered key")
                try:
                    key = bytes.fromhex(keys.get_secret(device_id))
                    _validate(ctx, key, False)
                    return
                except ApduError as e:
                    # Delete wrong key and fall through to prompt
                    if e.sw == SW.INCORRECT_PARAMETERS:
                        logger.debug("Remembered key incorrect, deleting key")
                        del keys[device_id]
                        keys.write()
                except Exception as e:
                    # Other error, fall though to prompt
                    logger.warning("Error authenticating", exc_info=e)

            # Prompt for password
            password = click_prompt(prompt, hide_input=True)
            key = session.derive_key(password)
            _validate(ctx, key, remember)
        except ApduError:
            raise CliFail("Authentication to the YubiKey failed. Wrong password?")

    elif password:
        raise CliFail("Password provided, but no password is set.")


@oath.group()
def access():
    """Manage password protection for OATH."""


@access.command()
@click.pass_context
@click_password_option
@click.option(
    "-c",
    "--clear",
    is_flag=True,
    help="remove the current password",
)
@click.option("-n", "--new-password", help="provide a new password as an argument")
@click_remember_option
def change(ctx, password, clear, new_password, remember):
    """
    Change the password used to protect OATH accounts.

    Allows you to set or change a password that will be required to access the OATH
    accounts stored on the YubiKey.
    """
    if clear and new_password:
        ctx.fail("--clear cannot be combined with --new-password.")

    _init_session(ctx, password, False, prompt="Enter the current password")

    session = ctx.obj["session"]
    keys = ctx.obj["oath_keys"]
    device_id = session.device_id

    if clear:
        session.unset_key()
        if device_id in keys:
            del keys[device_id]
            keys.write()
            logger.info("Deleted remembered access key")

        click.echo("Password cleared from YubiKey.")
    else:
        if remember:
            try:
                keys.ensure_unlocked()
            except ValueError:
                raise CliFail(
                    "Failed to remember password, the keyring is locked or unavailable."
                )
        if not new_password:
            new_password = click_prompt(
                "Enter the new password", hide_input=True, confirmation_prompt=True
            )
        key = session.derive_key(new_password)
        if remember:
            keys.put_secret(device_id, key.hex())
            keys.write()
            click.echo("Password remembered.")
        elif device_id in keys:
            del keys[device_id]
            keys.write()
        session.set_key(key)
        click.echo("Password updated.")


@access.command()
@click.pass_context
@click_password_option
def remember(ctx, password):
    """
    Store the YubiKeys password on this computer to avoid having to enter it
    on each use.
    """
    session = ctx.obj["session"]
    device_id = session.device_id
    keys = ctx.obj["oath_keys"]

    if not session.locked:
        if device_id in keys:
            del keys[session.device_id]
            keys.write()
            logger.info("Deleted remembered access key")
        click.echo("This YubiKey is not password protected.")
    else:
        try:
            keys.ensure_unlocked()
        except ValueError:
            raise CliFail(
                "Failed to remember password, the keyring is locked or unavailable."
            )
        if not password:
            password = click_prompt("Enter the password", hide_input=True)
        key = session.derive_key(password)
        try:
            _validate(ctx, key, True)
        except Exception:
            raise CliFail("Authentication to the YubiKey failed. Wrong password?")


def _clear_all_passwords(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return

    keys = AppData("oath_keys")
    if keys:
        keys.clear()
        keys.write()
    click.echo("All passwords have been forgotten.")
    ctx.exit()


@access.command()
@click.pass_context
@click.option(
    "-a",
    "--all",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_clear_all_passwords,
    help="remove all stored passwords",
)
def forget(ctx):
    """
    Remove a stored password from this computer.
    """
    session = ctx.obj["session"]
    device_id = session.device_id
    keys = ctx.obj["oath_keys"]

    if device_id in keys:
        del keys[session.device_id]
        keys.write()
        logger.info("Deleted remembered access key")
        click.echo("Password forgotten.")
    else:
        click.echo("No password stored for this YubiKey.")


click_touch_option = click.option(
    "-t", "--touch", is_flag=True, help="require touch on YubiKey to generate code"
)


click_show_hidden_option = click.option(
    "-H", "--show-hidden", is_flag=True, help="include hidden accounts"
)


def _string_id(credential):
    return credential.id.decode("utf-8")


def _error_multiple_hits(ctx, hits):
    click.echo(
        "Error: Multiple matches, please make the query more specific.", err=True
    )
    click.echo("", err=True)
    for cred in hits:
        click.echo(_string_id(cred), err=True)
    ctx.exit(1)


def _search(creds, query, show_hidden):
    hits = []
    for c in creds:
        cred_id = _string_id(c)
        if not show_hidden and is_hidden(c):
            continue
        if cred_id == query:
            return [c]
        if query.lower() in cred_id.lower():
            hits.append(c)
    return hits


@oath.group()
def accounts():
    """Manage and use OATH accounts."""


@accounts.command()
@click.argument("name")
@click.argument("secret", callback=click_parse_b32_key, required=False)
@click.option(
    "-o",
    "--oath-type",
    type=EnumChoice(OATH_TYPE),
    default=OATH_TYPE.TOTP.name,
    help="time-based (TOTP) or counter-based (HOTP) account",
    show_default=True,
)
@click.option(
    "-d",
    "--digits",
    type=click.Choice(["6", "7", "8"]),
    default="6",
    help="number of digits in generated code",
    show_default=True,
)
@click.option(
    "-a",
    "--algorithm",
    type=EnumChoice(HASH_ALGORITHM),
    default=HASH_ALGORITHM.SHA1.name,
    show_default=True,
    help="algorithm to use for code generation",
)
@click.option(
    "-c",
    "--counter",
    type=click.INT,
    default=0,
    help="initial counter value for HOTP accounts",
)
@click.option("-i", "--issuer", help="issuer of the account (optional)")
@click.option(
    "-P",
    "--period",
    help="number of seconds a TOTP code is valid",
    default=30,
    show_default=True,
)
@click_touch_option
@click_force_option
@click_password_option
@click_remember_option
@click.pass_context
def add(
    ctx,
    secret,
    name,
    issuer,
    period,
    oath_type,
    digits,
    touch,
    algorithm,
    counter,
    force,
    password,
    remember,
):
    """
    Add a new account.

    This will add a new OATH account to the YubiKey.

    \b
    NAME    human readable name of the account, such as a username or e-mail address
    SECRET  base32-encoded secret/key value provided by the server
    """

    digits = int(digits)

    if not secret:
        while True:
            secret = click_prompt("Enter a secret key (base32)")
            try:
                secret = parse_b32_key(secret)
                break
            except Exception as e:
                click.echo(e)

    _init_session(ctx, password, remember)

    _add_cred(
        ctx,
        CredentialData(
            name, oath_type, algorithm, secret, digits, period, counter, issuer
        ),
        touch,
        force,
    )


@click_callback()
def click_parse_uri(ctx, param, val):
    try:
        return CredentialData.parse_uri(val)
    except ValueError:
        raise click.BadParameter("URI seems to have the wrong format.")


@accounts.command()
@click.argument("data", callback=click_parse_uri, required=False, metavar="URI")
@click_touch_option
@click_force_option
@click_password_option
@click_remember_option
@click.pass_context
def uri(ctx, data, touch, force, password, remember):
    """
    Add a new account from an otpauth:// URI.

    Use a URI to add a new account to the YubiKey.
    """

    if not data:
        while True:
            uri = click_prompt("Enter an OATH URI (otpauth://)")
            try:
                data = CredentialData.parse_uri(uri)
                break
            except Exception as e:
                click.echo(e)

    # Steam is a special case where we allow the otpauth
    # URI to contain a 'digits' value of '5'.
    if data.digits == 5 and is_steam(data):
        data.digits = 6

    _init_session(ctx, password, remember)
    _add_cred(ctx, data, touch, force)


def _add_cred(ctx, data, touch, force):
    session = ctx.obj["session"]
    version = session.version

    if not (0 < len(data.name) <= 64):
        ctx.fail("Name must be between 1 and 64 bytes.")

    if len(data.secret) < 2:
        ctx.fail("Secret must be at least 2 bytes.")

    if touch and version < (4, 2, 6):
        raise CliFail("Require touch is not supported on this YubiKey.")

    if data.counter and data.oath_type != OATH_TYPE.HOTP:
        ctx.fail("Counter only supported for HOTP accounts.")

    if data.hash_algorithm == HASH_ALGORITHM.SHA512 and (
        version < (4, 3, 1) or is_yk4_fips(ctx.obj["info"])
    ):
        raise CliFail("Algorithm SHA512 not supported on this YubiKey.")

    creds = session.list_credentials()
    cred_id = data.get_id()
    if not force and any(cred.id == cred_id for cred in creds):
        click.confirm(
            f"An account called {data.name} already exists on this YubiKey."
            " Do you want to overwrite it?",
            abort=True,
            err=True,
        )

    firmware_overwrite_issue = (4, 0, 0) < version < (4, 3, 5)
    cred_is_subset = any(
        (cred.id.startswith(cred_id) and cred.id != cred_id) for cred in creds
    )

    #  YK4 has an issue with credential overwrite in firmware versions < 4.3.5
    if firmware_overwrite_issue and cred_is_subset:
        raise CliFail("Choose a name that is not a subset of an existing account.")

    try:
        session.put_credential(data, touch)
    except ApduError as e:
        if e.sw == SW.NO_SPACE:
            raise CliFail("No space left on the YubiKey for OATH accounts.")
        elif e.sw == SW.COMMAND_ABORTED:
            # Some NEOs do not use the NO_SPACE error.
            raise CliFail("The command failed. Is there enough space on the YubiKey?")
        else:
            raise


@accounts.command()
@click_show_hidden_option
@click.pass_context
@click.option("-o", "--oath-type", is_flag=True, help="display the OATH type")
@click.option("-P", "--period", is_flag=True, help="display the period")
@click_password_option
@click_remember_option
def list(ctx, show_hidden, oath_type, period, password, remember):
    """
    List all accounts.

    List all accounts stored on the YubiKey.
    """
    _init_session(ctx, password, remember)
    session = ctx.obj["session"]
    creds = [
        cred
        for cred in session.list_credentials()
        if show_hidden or not is_hidden(cred)
    ]
    creds.sort()
    for cred in creds:
        click.echo(_string_id(cred), nl=False)
        if oath_type:
            click.echo(f", {cred.oath_type.name}", nl=False)
        if period:
            click.echo(f", {cred.period}", nl=False)
        click.echo()


@accounts.command()
@click_show_hidden_option
@click.pass_context
@click.argument("query", required=False, default="")
@click.option(
    "-s",
    "--single",
    is_flag=True,
    help="ensure only a single match, and output only the code",
)
@click_password_option
@click_remember_option
def code(ctx, show_hidden, query, single, password, remember):
    """
    Generate codes.

    Generate codes from OATH accounts stored on the YubiKey.
    Provide a query string to match one or more specific accounts.
    Accounts of type HOTP, or those that require touch, requre a single match to be
    triggered.
    """

    _init_session(ctx, password, remember)

    session = ctx.obj["session"]
    try:
        entries = session.calculate_all()
    except ApduError as e:
        if e.sw == SW.MEMORY_FAILURE:
            logger.warning("Corrupted data in OATH accounts, attempting to fix")
            if delete_broken_credential(session):
                entries = session.calculate_all()
            else:
                logger.error("Unable to fix memory failure")
                raise
        else:
            raise

    creds = _search(entries.keys(), query, show_hidden)

    if len(creds) == 1:
        cred = creds[0]
        code = entries[cred]
        if cred.touch_required:
            prompt_for_touch()
        try:
            if cred.oath_type == OATH_TYPE.HOTP:
                with prompt_timeout():
                    # HOTP might require touch, we don't know.
                    # Assume yes after 500ms.
                    code = session.calculate_code(cred)
            elif code is None:
                code = session.calculate_code(cred)
        except ApduError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                raise CliFail("Touch account timed out!")
        entries[cred] = code

    elif single and len(creds) > 1:
        _error_multiple_hits(ctx, creds)

    elif single and len(creds) == 0:
        raise CliFail("No matching account found.")

    if single and creds:
        if is_steam(cred):
            click.echo(calculate_steam(session, cred))
        else:
            click.echo(code.value)
    else:
        outputs = []
        for cred in sorted(creds):
            code = entries[cred]
            if code:
                if is_steam(cred):
                    code = calculate_steam(session, cred)
                else:
                    code = code.value
            elif cred.touch_required:
                code = "[Requires Touch]"
            elif cred.oath_type == OATH_TYPE.HOTP:
                code = "[HOTP Account]"
            else:
                code = ""
            outputs.append((_string_id(cred), code))

        longest_name = max(len(n) for (n, c) in outputs) if outputs else 0
        longest_code = max(len(c) for (n, c) in outputs) if outputs else 0
        format_str = "{:<%d}  {:>%d}" % (longest_name, longest_code)

        for name, result in outputs:
            click.echo(format_str.format(name, result))


@accounts.command()
@click.pass_context
@click.argument("query")
@click.argument("name")
@click.option("-f", "--force", is_flag=True, help="confirm rename without prompting")
@click_password_option
@click_remember_option
def rename(ctx, query, name, force, password, remember):
    """
    Rename an account (requires YubiKey 5.3 or later).

    \b
    QUERY  a query to match a single account (as shown in "list")
    NAME   the name of the account (use "<issuer>:<name>" to specify issuer)
    """

    _init_session(ctx, password, remember)
    session = ctx.obj["session"]
    creds = session.list_credentials()
    hits = _search(creds, query, True)
    if len(hits) == 0:
        click.echo("No matches, nothing to be done.")
    elif len(hits) == 1:
        cred = hits[0]
        if ":" in name:
            issuer, name = name.split(":", 1)
        else:
            issuer = None

        new_id = _format_cred_id(issuer, name, cred.oath_type, cred.period)
        if any(cred.id == new_id for cred in creds):
            raise CliFail(
                f"Another account with ID {new_id.decode()} "
                "already exists on this YubiKey."
            )
        if force or (
            click.confirm(
                f"Rename account: {_string_id(cred)} ?",
                default=False,
                err=True,
            )
        ):
            session.rename_credential(cred.id, name, issuer)
            click.echo(f"Renamed {_string_id(cred)} to {new_id.decode()}.")
        else:
            click.echo("Rename aborted by user.")

    else:
        _error_multiple_hits(ctx, hits)


@accounts.command()
@click.pass_context
@click.argument("query")
@click.option("-f", "--force", is_flag=True, help="confirm deletion without prompting")
@click_password_option
@click_remember_option
def delete(ctx, query, force, password, remember):
    """
    Delete an account.

    Delete an account from the YubiKey.

    \b
    QUERY  a query to match a single account (as shown in "list")
    """

    _init_session(ctx, password, remember)
    session = ctx.obj["session"]
    creds = session.list_credentials()
    hits = _search(creds, query, True)
    if len(hits) == 0:
        click.echo("No matches, nothing to be done.")
    elif len(hits) == 1:
        cred = hits[0]
        if force or (
            click.confirm(
                f"Delete account: {_string_id(cred)} ?",
                default=False,
                err=True,
            )
        ):
            session.delete_credential(cred.id)
            click.echo(f"Deleted {_string_id(cred)}.")
        else:
            click.echo("Deletion aborted by user.")

    else:
        _error_multiple_hits(ctx, hits)
