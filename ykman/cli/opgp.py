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

from ..util import TRANSPORT
from ..opgp import OpgpController, KEY_SLOT, TOUCH_MODE
from ..driver_ccid import APDUError, SW_APPLICATION_NOT_FOUND
from .util import click_force_option, click_skip_on_help
import click

KEY_NAMES = dict(
    sig=KEY_SLOT.SIGN,
    enc=KEY_SLOT.ENCRYPT,
    aut=KEY_SLOT.AUTHENTICATE
)

MODE_NAMES = dict(
    off=TOUCH_MODE.OFF,
    on=TOUCH_MODE.ON,
    fixed=TOUCH_MODE.ON_FIXED
)


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
@click_skip_on_help
def openpgp(ctx):
    """
    Manage YubiKey OpenPGP functionality.
    """
    try:
        controller = OpgpController(ctx.obj['dev'].driver)
        ctx.obj['controller'] = controller
    except APDUError as e:
        if e.sw == SW_APPLICATION_NOT_FOUND:
            ctx.fail("The applet can't be found on the device.")
        raise


@openpgp.command()
@click.pass_context
def info(ctx):
    """
    Display status of OpenPGP functionality.
    """
    controller = ctx.obj['controller']
    click.echo('OpenPGP version: %d.%d.%d' % controller.version)


@openpgp.command()
@click.confirmation_option('-f', '--force', prompt='WARNING! This will delete '
                           'all stored OpenPGP keys and data and restore '
                           'factory settings?')
@click.pass_context
def reset(ctx):
    """
    Resets OpenPGP functionality.

    This action will wipe all OpenPGP data, and set all PINs to their default
    values.
    """
    click.echo('Resetting OpenPGP data...')
    ctx.obj['controller'].reset()
    echo_default_pins()


def echo_default_pins():
    click.echo('Success! All data has been cleared and default PINs are set.')
    click.echo('PIN:         123456')
    click.echo('Reset code:  NOT SET')
    click.echo('Admin PIN:   12345678')


@openpgp.command()
@click.argument('key', type=click.Choice(sorted(KEY_NAMES)),
                callback=lambda c, p, k: KEY_NAMES.get(k))
@click.argument('policy', type=click.Choice(sorted(MODE_NAMES)),
                callback=lambda c, p, k: MODE_NAMES.get(k), required=False)
@click.option('--admin-pin', required=False, metavar='PIN',
              help='Admin PIN for OpenPGP.')
@click_force_option
@click.pass_context
def touch(ctx, key, policy, admin_pin, force):
    """
    Manage touch policy for OpenPGP keys.

    \b
    KEY     Key slot to get/set (sig, enc or aut).
    POLICY  Touch policy to set (on, off or fixed).
    """
    controller = ctx.obj['controller']
    old_policy = controller.get_touch(key)
    click.echo('Current touch policy of {.name} key is {.name}.'.format(
        key, old_policy))
    if policy is None:
        return

    if old_policy == TOUCH_MODE.ON_FIXED:
        ctx.fail('A FIXED policy cannot be changed!')

    force or click.confirm('Set touch policy of {.name} key to {.name}?'.format(
        key, policy), abort=True)
    if admin_pin is None:
        admin_pin = click.prompt('Enter admin PIN', hide_input=True)
    controller.set_touch(key, policy, admin_pin.encode('utf8'))
    click.echo('Touch policy successfully set.')


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
        *pw_attempts), abort=True)
    controller.set_pin_retries(*(pw_attempts + (admin_pin.encode('utf8'),)))
    click.echo('PIN retries successfully set.')
    if resets_pins:
        echo_default_pins()


openpgp.transports = TRANSPORT.CCID
