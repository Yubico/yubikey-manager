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
from threading import Timer
from .util import (
    click_force_option, click_skip_on_help,
    click_callback, click_parse_b32_key,
    prompt_for_touch)
from ..driver_ccid import APDUError,  SW_APPLICATION_NOT_FOUND
from ..util import TRANSPORT, derive_key, parse_uri, parse_b32_key
from ..oath import OathController, SW

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
        ctx.obj['controller'].clear_password()
        click.echo('Password cleared.')
        ctx.exit()


@click_callback()
def click_parse_uri(ctx, param, val):
    try:
        return parse_uri(val)
    except ValueError:
        raise click.BadParameter('URI seems to have the wrong format.')


@click.group()
@click.pass_context
@click_skip_on_help
@click.option('-p', '--password', help='Provide a password to unlock device.')
def oath(ctx, password):
    """
    Manage YubiKey OATH credentials.
    """
    try:
        controller = OathController(ctx.obj['dev'].driver)
        ctx.obj['controller'] = controller
    except APDUError as e:
        if e.sw == SW_APPLICATION_NOT_FOUND:
            ctx.fail("The applet can't be found on the device.")
        raise

    if password and controller.locked:
        _validate(ctx, password)


@oath.command()
@click.pass_context
def info(ctx):
    """
    Display status of OATH functionality.
    """
    controller = ctx.obj['controller']
    version = controller.version
    click.echo(
        'OATH version: {}.{}.{}'.format(version[0], version[1], version[2]))


@oath.command()
@click.pass_context
@click.confirmation_option(
    '-f', '--force', prompt='WARNING! This will delete '
    'all stored OATH credentials and restore factory settings?')
def reset(ctx):
    """
    Reset all OATH data.

    This action will wipe all credentials and reset factory settings for
    the OATH functionality on the device.
    """

    click.echo('Resetting OATH data...')
    ctx.obj['controller'].reset()
    click.echo(
        'Success! All credentials have been cleared from the device.')


@oath.command()
@click.argument('name')
@click.argument('key', callback=click_parse_b32_key, required=False)
@click.option(
    '-o', '--oath-type', type=click.Choice(['TOTP', 'HOTP']), default='TOTP',
    help='Time-based (TOTP) or counter-based'
    ' (HOTP) credential (default is TOTP).')
@click.option(
    '-d', '--digits', type=click.Choice(['6', '8']), default='6',
    help='Number of digits in generated code (default is 6).')
@click.option(
    '-a', '--algorithm', type=click.Choice(['SHA1', 'SHA256']),
    default='SHA1', help='Algorithm to use for '
    'code generation (default is SHA1).')
@click.option(
    '-c', '--counter', type=click.INT, default=0,
    help='Initial counter value for HOTP credentials.')
@click_touch_option
@click_force_option
@click.pass_context
def add(ctx, key, name, oath_type, digits, touch, algorithm, counter, force):
    """
    Add a new credential.

    This will add a new credential to the device.
    """

    if not key:
        while True:
            key = click.prompt('Enter a secret key (base32)')
            try:
                key = parse_b32_key(key)
                break
            except Exception as e:
                click.echo(e)
                pass

    ensure_validated(ctx)

    _add_cred(
        ctx, key, name, oath_type, digits, touch, algorithm, counter, force)


@oath.command()
@click.argument('uri', callback=click_parse_uri, required=False)
@click_touch_option
@click_force_option
@click.pass_context
def uri(ctx, uri, touch, force):
    """
    Add a new credential from URI.

    Use a URI to add a new credential to the device.
    """

    if not uri:
        while True:
            uri = click.prompt('Enter an OATH URI')
            try:
                uri = parse_uri(uri)
                break
            except Exception as e:
                click.echo(e)
                pass

    ensure_validated(ctx)

    params = uri
    name = params.get('name')
    key = params.get('secret')
    key = parse_b32_key(key.upper())
    oath_type = params.get('type')
    digits = params.get('digits') or 6
    algo = params.get('algorithm') or 'SHA1'
    counter = params.get('counter') or 0

    # Steam is a special case where we allow the otpauth
    # URI to contain a 'digits' value of '5'.
    if digits == 5 and name.startswith('Steam:'):
        digits = 6

    _add_cred(ctx, key, name, oath_type, digits, touch, algo, counter, force)


def _add_cred(ctx, key, name, oath_type, digits, touch, algo, counter, force):

    controller = ctx.obj['controller']

    if len(name) not in range(1, 65):
        ctx.fail('Name must be between 1 and 64 bytes.')

    if len(key) < 2:
        ctx.fail('Key must be at least 2 bytes.')

    if touch and controller.version < (4, 2, 6):
        ctx.fail('Touch-required credentials not supported on this key.')

    if counter and not oath_type == 'hotp':
        ctx.fail('Counter only supported for HOTP credentials.')

    if not force and any(cred.name == name for cred in controller.list()):
        click.confirm(
            'A credential called {} already exists on the device.'
            ' Do you want to overwrite it?'.format(name), abort=True)

    firmware_overwrite_issue = (4, 0, 0) < controller.version < (4, 3, 5)
    cred_is_subset = any(
        (cred.name.startswith(name) and cred.name != name)
        for cred in controller.list())

    #  YK4 has an issue with credential overwrite in firmware versions < 4.3.5
    if firmware_overwrite_issue and cred_is_subset:
        ctx.fail(
            'Choose a name that is not a subset of an existing credential.')

    try:
        controller.put(
            key, name, oath_type=oath_type, digits=int(digits),
            require_touch=touch, algo=algo, counter=int(counter))
    except APDUError as e:
        if e.sw == SW.NO_SPACE:
            ctx.fail('No space left on device.')
        elif e.sw == SW.COMMAND_ABORTED:
            ctx.fail(
                'The command failed. Do you have enough space on the device?')
        else:
            raise


@oath.command()
@click_show_hidden_option
@click.pass_context
@click.option('-o', '--oath-type', is_flag=True, help='Display the OATH type.')
@click.option('-a', '--algorithm', is_flag=True, help='Display the algorithm.')
def list(ctx, show_hidden, oath_type, algorithm):
    """
    List all credentials.

    List all credentials stored on the device.
    """
    ensure_validated(ctx)
    controller = ctx.obj['controller']
    creds = [c for c in controller.list()]
    creds.sort()
    for cred in creds:
        if cred.hidden and not show_hidden:
            continue
        click.echo(cred.name, nl=False)
        if oath_type:
            click.echo(', {}'.format(cred.oath_type), nl=False)
        if algorithm:
            click.echo(', {}'.format(cred.algo), nl=False)
        click.echo()


@oath.command()
@click_show_hidden_option
@click.pass_context
@click.argument('query', required=False)
def code(ctx, show_hidden, query):
    """
    Generate codes.

    Generate codes from credentials stored on the device. \
Provide a query string to match one or more specific credentials. \
Touch and HOTP credentials require a single match to be triggered.
    """

    ensure_validated(ctx)

    controller = ctx.obj['controller']
    creds = [c for c in controller.calculate_all()]

    # Remove hidden creds
    if not show_hidden:
        creds = [c for c in creds if not c.hidden]
    if query:
        hits = _search(creds, query)
        if len(hits) == 1:
            cred = hits[0]
            if cred.touch:
                prompt_for_touch()
            if cred.oath_type == 'hotp':
                # HOTP might require touch, we don't know.
                # Assume yes after 500ms.
                hotp_touch_timer = Timer(0.500, prompt_for_touch)
                hotp_touch_timer.start()
                cred = controller.calculate(cred)
                hotp_touch_timer.cancel()
            else:
                cred = controller.calculate(cred)
            click.echo('{} {}'.format(cred.name, cred.code))
            ctx.exit()
        creds = hits

    longest = max(len(cred.name) for cred in creds) if creds else 0
    format_str = '{:<%d}  {:>10}' % longest

    creds.sort()

    for cred in creds:
        if cred.oath_type == 'totp':
            click.echo(format_str.format(cred.name, cred.code))
        if cred.touch:
            click.echo(format_str.format(cred.name, '[Touch Credential]'))
        if cred.oath_type == 'hotp':
            click.echo(format_str.format(cred.name, '[HOTP Credential]'))


@oath.command()
@click.pass_context
@click.argument('query')
def remove(ctx, query):
    """
    Remove a credential.

    Remove a credential from the device. \
Provide a query string to match the credential to remove.
    """

    ensure_validated(ctx)
    controller = ctx.obj['controller']
    creds = controller.list()
    hits = _search(creds, query)
    if len(hits) == 1:
        controller.delete(hits[0])
        click.echo('Removed {}.'.format(hits[0].name))
    else:
        click.echo('To many matches, please specify the query.')


@oath.command()
@click.pass_context
@click.option(
    '-c', '--clear', is_flag=True, expose_value=False,
    callback=_clear_callback, is_eager=True, help='Clear the current password.')
@click.option(
    '-n', '--new-password',
    help='Provide a new password as an argument.')
def password(ctx, new_password):
    """
    Password protect the OATH functionality.

    Allows you to require and set a password
    to access and use the OATH functionality
    on the device.
    """
    ensure_validated(ctx, prompt='Enter your current password')
    if not new_password:
        new_password = click.prompt(
            'Enter your new password',
            hide_input=True,
            confirmation_prompt=True)

    controller = ctx.obj['controller']
    key = derive_key(controller.id, new_password)
    controller.set_password(key)
    click.echo('New password set.')


def ensure_validated(ctx, prompt='Enter your password'):
    if ctx.obj['controller'].locked:
        password = click.prompt(prompt, hide_input=True)
        _validate(ctx, password)


def _validate(ctx, password):
    try:
        controller = ctx.obj['controller']
        key = derive_key(controller.id, password)
        controller.validate(key)
    except:
        ctx.fail('Authentication to the device failed. Wrong password?')


def _search(creds, query):
    hits = []
    for c in creds:
        if c.name == query:
            return [c]
        if query.lower() in c.name.lower():
            hits.append(c)
    return hits


oath.transports = TRANSPORT.CCID
