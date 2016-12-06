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
from .util import click_skip_on_help, parse_key
from ..driver_ccid import APDUError, SW_APPLICATION_NOT_FOUND
from ..util import TRANSPORT
from ..oath import OathController, OATH_TYPE


@click.group()
@click.pass_context
@click_skip_on_help
def oath(ctx):
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
    Reset all OATH credentials.

    This action will wipe all OATH data.
    """

    click.echo('Resetting OATH data...')
    ctx.obj['controller'].reset()


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
    '-t', '--touch', is_flag=True,
    help='Require touch on YubiKey to generate code.')
@click.pass_context
def add(ctx, key, name, oath_type, digits, touch):
    """
    Add a new OATH credential.

    This will add a new OATH credential to the device.
    """

    controller = ctx.obj['controller']

    if oath_type == 'hotp':
        oath_type = OATH_TYPE.HOTP
    else:
        oath_type = OATH_TYPE.TOTP

    if touch and controller.version < (4, 2, 6):
        ctx.fail("Touch-required credentials not supported on this key.")

    #  TODO: check if name already exists, prompt for confirmation.

    controller.put(
        key, name, oath_type=oath_type, digits=int(digits),
        require_touch=touch)


oath.transports = TRANSPORT.CCID
