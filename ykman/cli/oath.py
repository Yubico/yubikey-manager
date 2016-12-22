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
from .util import (
    click_force_option, click_skip_on_help,
    click_callback, parse_key, parse_b32_key)
from ..driver_ccid import APDUError,  SW_APPLICATION_NOT_FOUND
from ..util import TRANSPORT
from ..oath import OathController, SW
try:
    from urlparse import urlparse, parse_qs
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote, urlparse, parse_qs


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
        ctx.exit()


@click_callback()
def parse_uri(ctx, param, val):
    try:
        uri = val.strip()
        parsed = urlparse(uri)
        assert parsed.scheme == 'otpauth'
        params = dict((k, v[0]) for k, v in parse_qs(parsed.query).items())
        params['name'] = unquote(parsed.path)[1:]  # Unquote and strip leading /
        params['type'] = parsed.hostname
        # Issuer can come both in a param and inside name param.
        # We store both in the name field on the key.
        if 'issuer' in params \
                and not params['name'].startswith(params['issuer']):
                    params['name'] = params['issuer'] + ':' + params['name']
        return params
    except:
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

    if password and controller._challenge:
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
        "OATH version: {}.{}.{}".format(version[0], version[1], version[2]))


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
@click.argument('key', callback=parse_key)
@click.argument('name')
@click.option(
    '-o', '--oath-type', type=click.Choice(['totp', 'hotp']), default='totp',
    help='Specify whether this is a time or counter-based OATH credential.')
@click.option(
    '-d', '--digits', type=click.Choice(['6', '8']), default='6',
    help='Number of digits in generated code.')
@click.option(
    '-a', '--algorithm', type=click.Choice(['SHA1', 'SHA256']),
    default='SHA1', help='Algorithm to use for code generation.')
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

    ensure_validated(ctx)

    _add_cred(
        ctx, key, name, oath_type, digits, touch, algorithm, counter, force)


@oath.command()
@click.argument('uri', callback=parse_uri)
@click_touch_option
@click_force_option
@click.pass_context
def uri(ctx, uri, touch, force):
    """
    Add a new credential from URI.

    Use a URI to add a new credential to the device.
    """

    ensure_validated(ctx)

    params = uri
    name = params.get('name')
    key = params.get('secret')
    key = parse_b32_key(key)
    oath_type = params.get('type')
    digits = params.get('digits') or 6
    algo = params.get('algorithm') or 'SHA1'
    counter = params.get('counter') or 0

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
def list(ctx, show_hidden):
    """
    List all credentials.

    List all credentials stored on the device.
    """
    ensure_validated(ctx)
    controller = ctx.obj['controller']

    # TODO: Options to list type and algo ?
    for cred in controller.list():
        if cred.hidden and not show_hidden:
            continue
        click.echo('{}'.format(cred.name))


@oath.command()
@click_show_hidden_option
@click.pass_context
@click.argument('query', required=False)
def code(ctx, show_hidden, query):
    """
    Generate codes.

    Generate codes from credentials stored on the device.
    """

    ensure_validated(ctx)

    controller = ctx.obj['controller']
    creds = controller.calculate_all()

    # Remove hidden creds
    if not show_hidden:
        creds = [c for c in creds if not c.hidden]

    if query:
        hits = _search(creds, query)
        if len(hits) == 1:
            cred = hits[0]
            if cred.touch:
                click.echo("Touch your YubiKey...")
            cred = controller.calculate(cred)
            click.echo(cred.code)
            ctx.exit()
        creds = hits

    for cred in creds:
        if cred.oath_type == 'totp':
            click.echo('{} {}'.format(cred.name, cred.code))
        if cred.touch:
            click.echo('{} {}'.format(cred.name, '[Touch Credential]'))
        if cred.oath_type == 'hotp':
            click.echo('{} {}'.format(cred.name, '[HOTP Credential]'))


@oath.command()
@click.pass_context
@click.argument('query')
def remove(ctx, query):
    """
    Remove a credential.

    Removes a credential from the device.
    """

    ensure_validated(ctx)
    controller = ctx.obj['controller']
    creds = controller.list()
    hits = _search(creds, query)
    if len(hits) == 1:
        controller.delete(hits[0])
    else:
        click.echo("To many matches, please specify the query.")


@oath.command()
@click.pass_context
@click.option(
    '-c', '--clear', is_flag=True, expose_value=False,
    callback=_clear_callback, is_eager=True, help='Clear the current password.')
@click.option(
    '-n', '--new-password',
    help='Set a password to protect the OATH functionality on the device.')
def password(ctx, new_password):
    """
    Password protect the OATH functionality.

    Allows you to set a password required
    to access and use the OATH functionality
    on the device.
    """
    ensure_validated(ctx)
    if not new_password:
        new_password = click.prompt(
            'Enter your new password',
            hide_input=True,
            confirmation_prompt=True)

    ctx.obj['controller'].set_password(new_password)


def ensure_validated(ctx):
    if ctx.obj['controller']._challenge:
        password = click.prompt('Enter your current password', hide_input=True)
        _validate(ctx, password)


def _validate(ctx, password):
    try:
        ctx.obj['controller'].validate(password)
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
