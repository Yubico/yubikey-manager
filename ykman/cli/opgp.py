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

import logging
import click
from ..util import TRANSPORT, parse_certificates, parse_private_key
from ..opgp import OpgpController, KEY_SLOT, TOUCH_MODE
from ..driver_ccid import APDUError, SW
from .util import (
    click_force_option, click_format_option, click_postpone_execution,
    UpperCaseChoice)


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
        raise ValueError('Invalid value: {}. Must be one of: {}'.format(
            key, ', '.join(data.keys())))
    return inner


def int_in_range(minval, maxval):
    def inner(val):
        intval = int(val)
        if minval <= intval <= maxval:
            return intval
        raise ValueError('Invalid value: {}. Must be in range {}-{}'.format(
            intval, minval, maxval))
    return inner


@click.group()
@click.pass_context
@click_postpone_execution
def openpgp(ctx):
    """
    Manage OpenPGP Application.

    Examples:

    \b
      Set the retries for PIN, Reset Code and Admin PIN to 10:
      $ ykman openpgp set-retries 10 10 10

    \b
      Require touch to use the authentication key:
      $ ykman openpgp set-touch aut on
    """
    try:
        ctx.obj['controller'] = OpgpController(ctx.obj['dev'].driver)
    except APDUError as e:
        if e.sw == SW.NOT_FOUND:
            ctx.fail("The OpenPGP application can't be found on this "
                     'YubiKey.')
        logger.debug('Failed to load OpenPGP Application', exc_info=e)
        ctx.fail('Failed to load OpenPGP Application')


@openpgp.command()
@click.pass_context
def info(ctx):
    """
    Display status of OpenPGP application.
    """
    controller = ctx.obj['controller']
    click.echo('OpenPGP version: %d.%d.%d' % controller.version)
    retries = controller.get_remaining_pin_tries()
    click.echo('PIN tries remaining: {}'.format(retries.pin))
    click.echo('Reset code tries remaining: {}'.format(retries.reset))
    click.echo('Admin PIN tries remaining: {}'.format(retries.admin))
    # Touch only available on YK4 and later
    if controller.version >= (4, 2, 6):
        click.echo()
        click.echo('Touch policies')
        click.echo(
            'Signature key           {!s}'.format(
                controller.get_touch(KEY_SLOT.SIGNATURE)))
        click.echo(
            'Encryption key          {!s}'.format(
                controller.get_touch(KEY_SLOT.ENCRYPTION)))
        click.echo(
            'Authentication key      {!s}'.format(
                controller.get_touch(KEY_SLOT.AUTHENTICATION)))
        try:
            click.echo(
                'Attestation key         {!s}'.format(
                    controller.get_touch(KEY_SLOT.ATTESTATION)))
        except APDUError:
            logger.debug('No attestation key slot found')


@openpgp.command()
@click.confirmation_option('-f', '--force', prompt='WARNING! This will delete '
                           'all stored OpenPGP keys and data and restore '
                           'factory settings?')
@click.pass_context
def reset(ctx):
    """
    Reset OpenPGP application.

    This action will wipe all OpenPGP data, and set all PINs to their default
    values.
    """
    click.echo("Resetting OpenPGP data, don't remove your YubiKey...")
    ctx.obj['controller'].reset()
    click.echo('Success! All data has been cleared and default PINs are set.')
    echo_default_pins()


def echo_default_pins():
    click.echo('PIN:         123456')
    click.echo('Reset code:  NOT SET')
    click.echo('Admin PIN:   12345678')


@openpgp.command('set-touch')
@click.argument(
    'key', metavar='KEY', type=UpperCaseChoice(['AUT', 'ENC', 'SIG', 'ATT']),
    callback=lambda c, p, v: KEY_SLOT(v))
@click.argument(
    'policy', metavar='POLICY',
    type=UpperCaseChoice(['ON', 'OFF', 'FIXED', 'CACHED', 'CACHED-FIXED']),
    callback=lambda c, p, v: TOUCH_MODE[v.replace('-', '_')])
@click.option('-a', '--admin-pin', help='Admin PIN for OpenPGP.')
@click_force_option
@click.pass_context
def set_touch(ctx, key, policy, admin_pin, force):
    """
    Set touch policy for OpenPGP keys.

    \b
    KEY     Key slot to set (sig, enc, aut or att).
    POLICY  Touch policy to set (on, off, fixed, cached or cached-fix).
    """
    controller = ctx.obj['controller']

    if admin_pin is None:
        admin_pin = click.prompt('Enter admin PIN', hide_input=True, err=True)

    if force or click.confirm(
            'Set touch policy of {} key to {}?'.format(
                key.name.lower(),
                policy.name.lower().replace('_', '-')),
                abort=True, err=True):
        try:
            controller.set_touch(key, policy, admin_pin)
        except APDUError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                ctx.fail('Touch policy not allowed.')
            logger.debug('Failed to set touch policy', exc_info=e)
            ctx.fail('Failed to set touch policy.')


@openpgp.command('set-pin-retries')
@click.argument('pw-attempts', nargs=3, type=click.IntRange(1, 99))
@click.password_option('--admin-pin', metavar='PIN', prompt='Enter admin PIN',
                       confirmation_prompt=False)
@click_force_option
@click.pass_context
def set_pin_retries(ctx, pw_attempts, admin_pin, force):
    """
    Manage pin-retries.

    Sets the number of attempts available before locking for each PIN.

    PW_ATTEMPTS should be three integer values corresponding to the number of
    attempts for the PIN, Reset Code, and Admin PIN, respectively.
    """
    controller = ctx.obj['controller']
    resets_pins = controller.version < (4, 0, 0)
    if resets_pins:
        click.echo('WARNING: Setting PIN retries will reset the values for all '
                   '3 PINs!')
    force or click.confirm('Set PIN retry counters to: {} {} {}?'.format(
        *pw_attempts), abort=True, err=True)
    controller.set_pin_retries(*(pw_attempts + (admin_pin.encode('utf8'),)))
    click.echo('PIN retries successfully set.')
    if resets_pins:
        click.echo('Default PINs are set.')
        echo_default_pins()


openpgp.transports = TRANSPORT.CCID
