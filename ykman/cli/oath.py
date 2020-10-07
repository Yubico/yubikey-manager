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
from threading import Timer
from .util import (
    click_force_option,
    click_postpone_execution,
    click_callback,
    click_parse_b32_key,
    prompt_for_touch,
    EnumChoice,
)
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import ApduError, SW
from yubikit.oath import (
    OathSession,
    CredentialData,
    OATH_TYPE,
    HASH_ALGORITHM,
    parse_b32_key,
)
from ..oath import is_steam, calculate_steam, is_hidden
from ..device import is_fips_version
from ..settings import Settings


logger = logging.getLogger(__name__)

click_touch_option = click.option(
    "-t", "--touch", is_flag=True, help="Require touch on YubiKey to generate code."
)


click_show_hidden_option = click.option(
    "-H", "--show-hidden", is_flag=True, help="Include hidden credentials."
)


def _string_id(credential):
    return credential.id.decode("utf-8")


@click_callback()
def _clear_callback(ctx, param, clear):
    if clear:
        ensure_validated(ctx)
        app = ctx.obj["controller"]
        settings = ctx.obj["settings"]

        app.unset_key()
        keys = settings.setdefault("keys", {})
        if app.info.device_id in keys:
            del keys[app.info.device_id]
            settings.write()

        click.echo("Password cleared.")
        ctx.exit()
    return clear


@click_callback()
def click_parse_uri(ctx, param, val):
    try:
        return CredentialData.parse_uri(val)
    except ValueError:
        raise click.BadParameter("URI seems to have the wrong format.")


@click.group()
@click.pass_context
@click_postpone_execution
@click.option("-p", "--password", help="Provide a password to unlock the " "YubiKey.")
def oath(ctx, password):
    """
    Manage OATH Application.

    Examples:

    \b
      Generate codes for credentials starting with 'yubi':
      $ ykman oath code yubi

    \b
      Add a touch credential with the secret key f5up4ub3dw and the name yubico:
      $ ykman oath add yubico f5up4ub3dw --touch

    \b
      Set a password for the OATH application:
      $ ykman oath set-password
    """
    try:
        controller = OathSession(ctx.obj["conn"])
        ctx.obj["controller"] = controller
        ctx.obj["settings"] = Settings("oath")
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            ctx.fail("The OATH application can't be found on this YubiKey.")
        raise

    if password:
        ctx.obj["key"] = controller.derive_key(password)


@oath.command()
@click.pass_context
def info(ctx):
    """
    Display status of OATH application.
    """
    app = ctx.obj["controller"]
    version = app.info.version
    click.echo("OATH version: {}.{}.{}".format(version[0], version[1], version[2]))
    click.echo("Password protection " + ("enabled" if app.locked else "disabled"))

    keys = ctx.obj["settings"].get("keys", {})
    if app.locked and app.info.device_id in keys:
        click.echo("The password for this YubiKey is remembered by ykman.")

    if is_fips_version(version):
        click.echo("FIPS Approved Mode: {}".format("Yes" if app.locked else "No"))


@oath.command()
@click.pass_context
@click.confirmation_option(
    "-f",
    "--force",
    prompt="WARNING! This will delete "
    "all stored OATH credentials and restore factory settings?",
)
def reset(ctx):
    """
    Reset all OATH data.

    This action will wipe all credentials and reset factory settings for
    the OATH application on the YubiKey.
    """

    app = ctx.obj["controller"]
    click.echo("Resetting OATH data...")
    old_id = app.info.device_id
    app.reset()

    settings = ctx.obj["settings"]
    keys = settings.setdefault("keys", {})
    if old_id in keys:
        del keys[old_id]
        settings.write()

    click.echo("Success! All OATH credentials have been cleared from your YubiKey.")


@oath.command()
@click.argument("name")
@click.argument(
    "secret",
    callback=click_parse_b32_key,
    required=False,
    envvar="YKMAN_OATH_ADD_SECRET",
)
@click.option(
    "-o",
    "--oath-type",
    type=EnumChoice(OATH_TYPE),
    default=OATH_TYPE.TOTP.name,
    help="Time-based (TOTP) or counter-based (HOTP) credential.",
    show_default=True,
)
@click.option(
    "-d",
    "--digits",
    type=click.Choice(["6", "7", "8"]),
    default="6",
    help="Number of digits in generated code.",
    show_default=True,
)
@click.option(
    "-a",
    "--algorithm",
    type=EnumChoice(HASH_ALGORITHM),
    default=HASH_ALGORITHM.SHA1.name,
    show_default=True,
    help="Algorithm to use for code generation.",
)
@click.option(
    "-c",
    "--counter",
    type=click.INT,
    default=0,
    help="Initial counter value for HOTP credentials.",
)
@click.option("-i", "--issuer", help="Issuer of the credential.")
@click.option(
    "-p",
    "--period",
    help="Number of seconds a TOTP code is valid.",
    default=30,
    show_default=True,
)
@click_touch_option
@click_force_option
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
):
    """
    Add a new credential.

    This will add a new credential to your YubiKey.
    """

    digits = int(digits)

    if not secret:
        while True:
            secret = click.prompt("Enter a secret key (base32)", err=True)
            try:
                secret = parse_b32_key(secret)
                break
            except Exception as e:
                click.echo(e)

    ensure_validated(ctx)

    _add_cred(
        ctx,
        CredentialData(
            name, oath_type, algorithm, secret, digits, period, counter, issuer
        ),
        touch,
        force,
    )


@oath.command()
@click.argument(
    "uri", callback=click_parse_uri, required=False, envvar="YKMAN_OATH_URI_URI"
)
@click_touch_option
@click_force_option
@click.pass_context
def uri(ctx, uri, touch, force):
    """
    Add a new credential from URI.

    Use a URI to add a new credential to your YubiKey.
    """

    if not uri:
        while True:
            uri = click.prompt("Enter an OATH URI", err=True)
            try:
                uri = CredentialData.parse_uri(uri)
                break
            except Exception as e:
                click.echo(e)

    ensure_validated(ctx)
    data = uri

    # Steam is a special case where we allow the otpauth
    # URI to contain a 'digits' value of '5'.
    if data.digits == 5 and is_steam(data):
        data.digits = 6

    _add_cred(ctx, data, touch, force)


def _add_cred(ctx, data, touch, force):
    app = ctx.obj["controller"]
    version = app.info.version

    if not (0 < len(data.name) <= 64):
        ctx.fail("Name must be between 1 and 64 bytes.")

    if len(data.secret) < 2:
        ctx.fail("Secret must be at least 2 bytes.")

    if touch and version < (4, 2, 6):
        ctx.fail("Touch-required credentials not supported on this key.")

    if data.counter and data.oath_type != OATH_TYPE.HOTP:
        ctx.fail("Counter only supported for HOTP credentials.")

    if data.hash_algorithm == HASH_ALGORITHM.SHA512 and (
        version < (4, 3, 1) or is_fips_version(version)
    ):
        ctx.fail("Algorithm SHA512 not supported on this YubiKey.")

    creds = app.list_credentials()
    cred_id = data.get_id()
    if not force and any(cred.id == cred_id for cred in creds):
        click.confirm(
            "A credential called {} already exists on this YubiKey."
            " Do you want to overwrite it?".format(data.name),
            abort=True,
            err=True,
        )

    firmware_overwrite_issue = (4, 0, 0) < version < (4, 3, 5)
    cred_is_subset = any(
        (cred.id.startswith(cred_id) and cred.id != cred_id) for cred in creds
    )

    #  YK4 has an issue with credential overwrite in firmware versions < 4.3.5
    if firmware_overwrite_issue and cred_is_subset:
        ctx.fail("Choose a name that is not a subset of an existing credential.")

    try:
        app.put_credential(data, touch)
    except ApduError as e:
        if e.sw == SW.NO_SPACE:
            ctx.fail("No space left on your YubiKey for OATH credentials.")
        elif e.sw == SW.COMMAND_ABORTED:
            # Some NEOs do not use the NO_SPACE error.
            ctx.fail("The command failed. Is there enough space on your YubiKey?")
        else:
            raise


@oath.command()
@click_show_hidden_option
@click.pass_context
@click.option("-o", "--oath-type", is_flag=True, help="Display the OATH type.")
@click.option("-p", "--period", is_flag=True, help="Display the period.")
def list(ctx, show_hidden, oath_type, period):
    """
    List all credentials.

    List all credentials stored on your YubiKey.
    """
    ensure_validated(ctx)
    controller = ctx.obj["controller"]
    creds = [
        cred
        for cred in controller.list_credentials()
        if show_hidden or not is_hidden(cred)
    ]
    creds.sort()
    for cred in creds:
        click.echo(_string_id(cred), nl=False)
        if oath_type:
            click.echo(u", {}".format(cred.oath_type.name), nl=False)
        if period:
            click.echo(", {}".format(cred.period), nl=False)
        click.echo()


@oath.command()
@click_show_hidden_option
@click.pass_context
@click.argument("query", required=False, default="")
@click.option(
    "-s",
    "--single",
    is_flag=True,
    help="Ensure only a single match, and output only the code.",
)
def code(ctx, show_hidden, query, single):
    """
    Generate codes.

    Generate codes from credentials stored on your YubiKey.
    Provide a query string to match one or more specific credentials.
    Touch and HOTP credentials require a single match to be triggered.
    """

    ensure_validated(ctx)

    app = ctx.obj["controller"]
    entries = app.calculate_all()
    creds = _search(entries.keys(), query, show_hidden)

    if len(creds) == 1:
        cred = creds[0]
        code = entries[cred]
        if cred.touch_required:
            prompt_for_touch()
        try:
            if cred.oath_type == OATH_TYPE.HOTP:
                # HOTP might require touch, we don't know.
                # Assume yes after 500ms.
                hotp_touch_timer = Timer(0.500, prompt_for_touch)
                hotp_touch_timer.start()
                code = app.calculate_code(cred)
                hotp_touch_timer.cancel()
            elif code is None:
                code = app.calculate_code(cred)
        except ApduError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                ctx.fail("Touch credential timed out!")
        entries[cred] = code

    elif single and len(creds) > 1:
        _error_multiple_hits(ctx, creds)

    elif single and len(creds) == 0:
        ctx.fail("No matching credential found.")

    if single and creds:
        if is_steam(cred):
            click.echo(calculate_steam(app, cred))
        else:
            click.echo(code.value)
    else:
        outputs = []
        for cred in sorted(creds):
            code = entries[cred]
            if code:
                code = code.value
            elif cred.touch_required:
                code = "[Touch Credential]"
            elif cred.oath_type == OATH_TYPE.HOTP:
                code = "[HOTP Credential]"
            else:
                code = ""
            if is_steam(cred):
                code = calculate_steam(app, cred)
            outputs.append((_string_id(cred), code))

        longest_name = max(len(n) for (n, c) in outputs) if outputs else 0
        longest_code = max(len(c) for (n, c) in outputs) if outputs else 0
        format_str = u"{:<%d}  {:>%d}" % (longest_name, longest_code)

        for name, result in outputs:
            click.echo(format_str.format(name, result))


@oath.command()
@click.pass_context
@click.argument("query")
@click.option("-f", "--force", is_flag=True, help="Confirm deletion without prompting")
def delete(ctx, query, force):
    """
    Delete a credential.

    Delete a credential from your YubiKey.
    Provide a query string to match the credential to delete.
    """

    ensure_validated(ctx)
    app = ctx.obj["controller"]
    creds = app.list_credentials()
    hits = _search(creds, query, True)
    if len(hits) == 0:
        click.echo("No matches, nothing to be done.")
    elif len(hits) == 1:
        cred = hits[0]
        if force or (
            click.confirm(
                u"Delete credential: {} ?".format(_string_id(cred)),
                default=False,
                err=True,
            )
        ):
            app.delete_credential(cred.id)
            click.echo(u"Deleted {}.".format(_string_id(cred)))
        else:
            click.echo("Deletion aborted by user.")

    else:
        _error_multiple_hits(ctx, hits)


@oath.command("set-password")
@click.pass_context
@click.option(
    "-c",
    "--clear",
    is_flag=True,
    expose_value=False,
    callback=_clear_callback,
    is_eager=True,
    help="Clear the current password.",
)
@click.option("-n", "--new-password", help="Provide a new password as an argument.")
@click.option(
    "-r", "--remember", is_flag=True, help="Remember the new password on this machine.",
)
def set_password(ctx, new_password, remember):
    """
    Password protect the OATH credentials.

    Allows you to set a password that will be required to access the OATH
    credentials stored on your YubiKey.
    """
    ensure_validated(ctx, prompt="Enter your current password")
    if not new_password:
        new_password = click.prompt(
            "Enter your new password",
            hide_input=True,
            confirmation_prompt=True,
            err=True,
        )

    app = ctx.obj["controller"]
    device_id = app.info.device_id
    settings = ctx.obj["settings"]
    keys = settings.setdefault("keys", {})
    key = app.derive_key(new_password)
    app.set_key(key)
    click.echo("Password updated.")
    if remember:
        keys[device_id] = key.hex()
        settings.write()
        click.echo("Password remembered")
    elif device_id in keys:
        del keys[device_id]
        settings.write()


@oath.command("remember-password")
@click.pass_context
@click.option("-F", "--forget", is_flag=True, help="Forget a password.")
@click.option(
    "-c",
    "--clear-all",
    is_flag=True,
    help="Remove all stored passwords from this computer.",
)
def remember_password(ctx, forget, clear_all):
    """
    Manage local password storage.

    Store your YubiKeys password on this computer to avoid having to enter it
    on each use, or delete stored passwords.
    """
    app = ctx.obj["controller"]
    device_id = app.info.device_id
    settings = ctx.obj["settings"]
    keys = settings.setdefault("keys", {})
    if clear_all:
        del settings["keys"]
        settings.write()
        click.echo("All passwords have been cleared.")
    elif forget:
        if device_id in keys:
            del keys[device_id]
            settings.write()
        click.echo("Password forgotten.")
    else:
        ensure_validated(ctx, remember=True)


def ensure_validated(ctx, prompt="Enter your password", remember=False):
    app = ctx.obj["controller"]
    device_id = app.info.device_id
    if app.locked:

        # If password given as arg, use it
        if "key" in ctx.obj:
            _validate(ctx, ctx.obj["key"], remember)
            return

        # Use stored key if available
        keys = ctx.obj["settings"].setdefault("keys", {})
        if device_id in keys:
            try:
                app.validate(bytes.fromhex(keys[device_id]))
                return
            except Exception as e:
                logger.debug("Error", exc_info=e)
                del keys[device_id]

        # Prompt for password
        password = click.prompt(prompt, hide_input=True, err=True)
        key = app.derive_key(password)
        _validate(ctx, key, remember)


def _validate(ctx, key, remember):
    try:
        app = ctx.obj["controller"]
        app.validate(key)
        if remember:
            settings = ctx.obj["settings"]
            keys = settings.setdefault("keys", {})
            keys[app.info.device_id] = key.hex()
            settings.write()
            click.echo("Password remembered.")
    except Exception:
        ctx.fail("Authentication to the YubiKey failed. Wrong password?")


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


def _error_multiple_hits(ctx, hits):
    click.echo(
        "Error: Multiple matches, please make the query more specific.", err=True
    )
    click.echo("", err=True)
    for cred in hits:
        click.echo(_string_id(cred), err=True)
    ctx.exit(1)


oath.transports = TRANSPORT.CCID  # type: ignore
