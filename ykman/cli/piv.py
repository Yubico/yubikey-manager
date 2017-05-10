# Copyright (c) 2017 Yubico AB
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
from ..piv import PivController
from ..driver_ccid import APDUError, SW_APPLICATION_NOT_FOUND
from .util import click_skip_on_help
import click


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
def piv(ctx):
    """
    Manage YubiKey OpenPGP functions.
    """
    try:
        controller = PivController(ctx.obj['dev'].driver)
        ctx.obj['controller'] = controller
    except APDUError as e:
        if e.sw == SW_APPLICATION_NOT_FOUND:
            ctx.fail("The applet can't be found on the device.")
        raise


@piv.command()
@click.pass_context
def info(ctx):
    """
    Display status of OpenPGP functionality.
    """
    controller = ctx.obj['controller']
    click.echo('PIV version: %d.%d.%d' % controller.version)
    # TODO: Add CHUID, CCC, slot info


@piv.command()
@click.pass_context
@click.confirmation_option(
    '-f', '--force', prompt='WARNING! This will delete '
    'all stored PIV data and restore factory settings. Proceed?')
def reset(ctx):
    """
    Reset all PIV data.

    This action will wipe all credentials and reset factory settings for
    the PIV functionality on the device.
    """

    click.echo('Resetting PIV data...')
    ctx.obj['controller'].reset()
    click.echo(
        'Success! All credentials have been cleared from the device.')
    click.echo('Your YubiKey now has the default PIN, PUK and Management Key:')
    click.echo('\tPIN:\t123456')
    click.echo('\tPUK:\t12345678')
    click.echo('\tKey:\t010203040506070801020304050607080102030405060708')


piv.transports = TRANSPORT.CCID
