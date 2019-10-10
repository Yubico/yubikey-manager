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

from __future__ import absolute_import
import click
import logging
from threading import Timer
from binascii import b2a_hex, a2b_hex
from .util import (
    click_force_option, click_postpone_execution, click_callback,
    click_parse_b32_key, prompt_for_touch, EnumChoice
)
from ..driver_ccid import (
    APDUError,  SW
)
from ..util import TRANSPORT, parse_b32_key
from ..oath import OathController, CredentialData, OATH_TYPE, ALGO
from ..settings import Settings


logger = logging.getLogger(__name__)

click_touch_option = click.option(
    '-t', '--touch', is_flag=True,
    help='Require touch on YubiKey to generate code.')


click_show_hidden_option = click.option(
    '-H', '--show-hidden', is_flag=True,
    help='Include hidden credentials.')


@click_callback()
def _clear_callback(ctx, param, clear):
    if clear:
        ensure_validated(ctx)
        controller = ctx.obj['controller']
        settings = ctx.obj['settings']

        controller.clear_password()
        keys = settings.setdefault('keys', {})
        if controller.id in keys:
            del keys[controller.id]
            settings.write()

        click.echo('Password cleared.')
        ctx.exit()


@click_callback()
def click_parse_uri(ctx, param, val):
    try:
        return CredentialData.from_uri(val)
    except ValueError:
        raise click.BadParameter('URI seems to have the wrong format.')


@click.group()
@click.pass_context
@click_postpone_execution
@click.option('-p', '--password', help='Provide a password to unlock the '
              'YubiKey.')
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
        controller = OathController(ctx.obj['dev'].driver)
        ctx.obj['controller'] = controller
        ctx.obj['settings'] = Settings('oath')
    except APDUError as e:
        if e.sw == SW.NOT_FOUND:
            ctx.fail("The OATH application can't be found on this YubiKey.")
        raise

    if password:
        ctx.obj['key'] = controller.derive_key(password)


@oath.command()
@click.pass_context
def info(ctx):
    """
    Display status of OATH application.
    """
    controller = ctx.obj['controller']
    version = controller.version
    click.echo(
        'OATH version: {}.{}.{}'.format(version[0], version[1], version[2]))
    click.echo('Password protection ' +
               ('enabled' if controller.locked else 'disabled'))

    keys = ctx.obj['settings'].get('keys', {})
    if controller.locked and controller.id in keys:
        click.echo('The password for this YubiKey is remembered by ykman.')

    if ctx.obj['dev'].is_fips:
        click.echo('FIPS Approved Mode: {}'.format(
            'Yes' if controller.is_in_fips_mode else 'No'))


@oath.command()
@click.pass_context
@click.confirmation_option(
    '-f', '--force', prompt='WARNING! This will delete '
    'all stored OATH credentials and restore factory settings?')
def reset(ctx):
    """
    Reset all OATH data.

    This action will wipe all credentials and reset factory settings for
    the OATH application on the YubiKey.
    """

    controller = ctx.obj['controller']
    click.echo('Resetting OATH data...')
    old_id = controller.id
    controller.reset()

    settings = ctx.obj['settings']
    keys = settings.setdefault('keys', {})
    if old_id in keys:
        del keys[old_id]
        settings.write()

    click.echo(
        'Success! All OATH credentials have been cleared from your YubiKey.')


@oath.command()
@click.argument('name')
@click.argument('secret', callback=click_parse_b32_key, required=False)
@click.option(
    '-o', '--oath-type',
    type=EnumChoice(OATH_TYPE), default=OATH_TYPE.TOTP.name,
    help='Time-based (TOTP) or counter-based (HOTP) credential.',
    show_default=True)
@click.option(
    '-d', '--digits', type=click.Choice(['6', '7', '8']), default='6',
    help='Number of digits in generated code.', show_default=True)
@click.option(
    '-a', '--algorithm',
    type=EnumChoice(ALGO), default=ALGO.SHA1.name, show_default=True,
    help='Algorithm to use for code generation.')
@click.option(
    '-c', '--counter', type=click.INT, default=0,
    help='Initial counter value for HOTP credentials.')
@click.option('-i', '--issuer', help='Issuer of the credential.')
@click.option(
    '-p', '--period', help='Number of seconds a TOTP code is valid.',
    default=30, show_default=True)
@click_touch_option
@click_force_option
@click.pass_context
def add(ctx, secret, name, issuer, period, oath_type, digits, touch, algorithm,
        counter, force):
    """
    Add a new credential.

    This will add a new credential to your YubiKey.
    """

    digits = int(digits)

    if not secret:
        while True:
            secret = click.prompt('Enter a secret key (base32)', err=True)
            try:
                secret = parse_b32_key(secret)
                break
            except Exception as e:
                click.echo(e)

    ensure_validated(ctx)

    _add_cred(ctx, CredentialData(secret, issuer, name, oath_type, algorithm,
                                  digits, period, counter, touch), force)


@oath.command()
@click.argument('uri', callback=click_parse_uri, required=False)
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
            uri = click.prompt('Enter an OATH URI', err=True)
            try:
                uri = CredentialData.from_uri(uri)
                break
            except Exception as e:
                click.echo(e)

    ensure_validated(ctx)
    data = uri

    # Steam is a special case where we allow the otpauth
    # URI to contain a 'digits' value of '5'.
    if data.digits == 5 and data.issuer == 'Steam':
        data.digits = 6

    data.touch = touch

    _add_cred(ctx, data, force=force)


def _add_cred(ctx, data, force):
    controller = ctx.obj['controller']

    if not (0 < len(data.name) <= 64):
        ctx.fail('Name must be between 1 and 64 bytes.')

    if len(data.secret) < 2:
        ctx.fail('Secret must be at least 2 bytes.')

    if data.touch and controller.version < (4, 2, 6):
        ctx.fail('Touch-required credentials not supported on this key.')

    if data.counter and data.oath_type != OATH_TYPE.HOTP:
        ctx.fail('Counter only supported for HOTP credentials.')

    if data.algorithm == ALGO.SHA512 and (
            controller.version < (4, 3, 1) or ctx.obj['dev'].is_fips):
        ctx.fail('Algorithm SHA512 not supported on this YubiKey.')

    key = data.make_key()
    if not force and any(cred.key == key for cred in controller.list()):
        click.confirm(
            'A credential called {} already exists on this YubiKey.'
            ' Do you want to overwrite it?'.format(data.name), abort=True,
            err=True)

    firmware_overwrite_issue = (4, 0, 0) < controller.version < (4, 3, 5)
    cred_is_subset = any(
        (cred.key.startswith(key) and cred.key != key)
        for cred in controller.list())

    #  YK4 has an issue with credential overwrite in firmware versions < 4.3.5
    if firmware_overwrite_issue and cred_is_subset:
        ctx.fail(
            'Choose a name that is not a subset of an existing credential.')

    try:
        controller.put(data)
    except APDUError as e:
        if e.sw == SW.NO_SPACE:
            ctx.fail('No space left on your YubiKey for OATH credentials.')
        elif e.sw == SW.COMMAND_ABORTED:
            # Some NEOs do not use the NO_SPACE error.
            ctx.fail(
                'The command failed. Is there enough space on your YubiKey?')
        else:
            raise


@oath.command()
@click_show_hidden_option
@click.pass_context
@click.option('-o', '--oath-type', is_flag=True, help='Display the OATH type.')
@click.option('-p', '--period', is_flag=True, help='Display the period.')
def list(ctx, show_hidden, oath_type, period):
    """
    List all credentials.

    List all credentials stored on your YubiKey.
    """
    ensure_validated(ctx)
    controller = ctx.obj['controller']
    creds = [cred
             for cred in controller.list()
             if show_hidden or not cred.is_hidden
             ]
    creds.sort()
    for cred in creds:
        click.echo(cred.printable_key, nl=False)
        if oath_type:
            click.echo(u', {}'.format(cred.oath_type.name), nl=False)
        if period:
            click.echo(', {}'.format(cred.period), nl=False)
        click.echo()


@oath.command()
@click_show_hidden_option
@click.pass_context
@click.argument('query', required=False, default='')
@click.option('-s', '--single', is_flag=True, help='Ensure only a single '
              'match, and output only the code.')
def code(ctx, show_hidden, query, single):
    """
    Generate codes.

    Generate codes from credentials stored on your YubiKey.
    Provide a query string to match one or more specific credentials.
    Touch and HOTP credentials require a single match to be triggered.
    """

    ensure_validated(ctx)

    controller = ctx.obj['controller']
    creds = [(cr, c)
             for (cr, c) in controller.calculate_all()
             if show_hidden or not cr.is_hidden
             ]

    creds = _search(creds, query)

    if len(creds) == 1:
        cred, code = creds[0]
        if cred.touch:
            prompt_for_touch()
        try:
            if cred.oath_type == OATH_TYPE.HOTP:
                # HOTP might require touch, we don't know.
                # Assume yes after 500ms.
                hotp_touch_timer = Timer(0.500, prompt_for_touch)
                hotp_touch_timer.start()
                creds = [(cred, controller.calculate(cred))]
                hotp_touch_timer.cancel()
            elif code is None:
                creds = [(cred, controller.calculate(cred))]
        except APDUError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                ctx.fail('Touch credential timed out!')

    elif single:
        _error_multiple_hits(ctx, [cr for cr, c in creds])

    if single:
        click.echo(creds[0][1].value)
    else:
        creds.sort()

        outputs = [
            (
                cr.printable_key,
                c.value if c
                else '[Touch Credential]' if cr.touch
                else '[HOTP Credential]' if cr.oath_type == OATH_TYPE.HOTP
                else ''
            ) for (cr, c) in creds
        ]

        longest_name = max(len(n) for (n, c) in outputs) if outputs else 0
        longest_code = max(len(c) for (n, c) in outputs) if outputs else 0
        format_str = u'{:<%d}  {:>%d}' % (longest_name, longest_code)

        for name, result in outputs:
            click.echo(format_str.format(name, result))


@oath.command()
@click.pass_context
@click.argument('query')
@click.option('-f', '--force', is_flag=True,
              help='Confirm deletion without prompting')
def delete(ctx, query, force):
    """
    Delete a credential.

    Delete a credential from your YubiKey.
    Provide a query string to match the credential to delete.
    """

    ensure_validated(ctx)
    controller = ctx.obj['controller']
    creds = controller.list()
    hits = _search(creds, query)
    if len(hits) == 0:
        click.echo('No matches, nothing to be done.')
    elif len(hits) == 1:
        cred = hits[0]
        if force or (click.confirm(
                u'Delete credential: {} ?'.format(cred.printable_key),
                default=False, err=True
        )):
            controller.delete(cred)
            click.echo(u'Deleted {}.'.format(cred.printable_key))
        else:
            click.echo('Deletion aborted by user.')

    else:
        _error_multiple_hits(ctx, hits)


@oath.command('set-password')
@click.pass_context
@click.option(
    '-c', '--clear', is_flag=True, expose_value=False,
    callback=_clear_callback, is_eager=True, help='Clear the current password.')
@click.option(
    '-n', '--new-password',
    help='Provide a new password as an argument.')
@click.option('-r', '--remember', is_flag=True, help='Remember the new '
              'password on this machine.')
def set_password(ctx, new_password, remember):
    """
    Password protect the OATH credentials.

    Allows you to set a password that will be required to access the OATH
    credentials stored on your YubiKey.
    """
    ensure_validated(ctx, prompt='Enter your current password')
    if not new_password:
        new_password = click.prompt(
            'Enter your new password',
            hide_input=True,
            confirmation_prompt=True,
            err=True)

    controller = ctx.obj['controller']
    settings = ctx.obj['settings']
    keys = settings.setdefault('keys', {})
    key = controller.set_password(new_password)
    click.echo('Password updated.')
    if remember:
        keys[controller.id] = b2a_hex(key).decode()
        settings.write()
        click.echo('Password remembered')
    elif controller.id in keys:
        del keys[controller.id]
        settings.write()


@oath.command('remember-password')
@click.pass_context
@click.option('-F', '--forget', is_flag=True, help='Forget a password.')
@click.option('-c', '--clear-all', is_flag=True, help='Remove all stored '
              'passwords from this computer.')
def remember_password(ctx, forget, clear_all):
    """
    Manage local password storage.

    Store your YubiKeys password on this computer to avoid having to enter it
    on each use, or delete stored passwords.
    """
    controller = ctx.obj['controller']
    settings = ctx.obj['settings']
    keys = settings.setdefault('keys', {})
    if clear_all:
        del settings['keys']
        settings.write()
        click.echo('All passwords have been cleared.')
    elif forget:
        if controller.id in keys:
            del keys[controller.id]
            settings.write()
        click.echo('Password forgotten.')
    else:
        ensure_validated(ctx, remember=True)


def ensure_validated(ctx, prompt='Enter your password', remember=False):
    controller = ctx.obj['controller']
    if controller.locked:

        # If password given as arg, use it
        if 'key' in ctx.obj:
            _validate(ctx, ctx.obj['key'], remember)
            return

        # Use stored key if available
        keys = ctx.obj['settings'].setdefault('keys', {})
        if controller.id in keys:
            try:
                controller.validate(a2b_hex(keys[controller.id]))
                return
            except Exception as e:
                logger.debug('Error', exc_info=e)
                del keys[controller.id]

        # Prompt for password
        password = click.prompt(prompt, hide_input=True, err=True)
        key = controller.derive_key(password)
        _validate(ctx, key, remember)


def _validate(ctx, key, remember):
    try:
        controller = ctx.obj['controller']
        controller.validate(key)
        if remember:
            settings = ctx.obj['settings']
            keys = settings.setdefault('keys', {})
            keys[controller.id] = b2a_hex(key).decode()
            settings.write()
            click.echo('Password remembered.')
    except Exception:
        ctx.fail('Authentication to the YubiKey failed. Wrong password?')


def _search(creds, query):
    hits = []
    for entry in creds:
        c = entry[0] if isinstance(entry, tuple) else entry
        if c.printable_key == query:
            return [entry]
        if query.lower() in c.printable_key.lower():
            hits.append(entry)
    return hits


def _error_multiple_hits(ctx, hits):
    click.echo(
        'Error: Multiple matches, please make the query more specific.',
        err=True
    )
    click.echo('', err=True)
    for cred in hits:
        click.echo(cred.printable_key, err=True)
    ctx.exit(1)


oath.transports = TRANSPORT.CCID
