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

from __future__ import absolute_import, print_function

from ykman import __version__
from ..util import TRANSPORT
from ..native.pyusb import get_usb_backend_version
from ..driver_otp import libversion as ykpers_version
from ..driver_u2f import libversion as u2fhost_version
from ..descriptor import get_descriptors, FailedOpeningDeviceException
from .util import click_skip_on_help
from .info import info
from .mode import mode
from .slot import slot
from .opgp import openpgp
from .oath import oath
from .piv import piv
import usb.core
import click
import sys


COMMANDS = (info, mode, slot, openpgp, oath, piv)


CLICK_CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help'],
    max_content_width=999
)


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('YubiKey Manager (ykman) version: {}'.format(__version__))
    libs = []
    libs.append('libykpers ' + (
        ykpers_version if ykpers_version is not None else 'not found!'))
    libs.append('libu2f-host ' + (
        u2fhost_version if u2fhost_version is not None else 'not found!'))
    usb_lib = get_usb_backend_version()
    libs.append(usb_lib or '<pyusb backend missing>')
    click.echo('Libraries:')
    for lib in libs:
        click.echo('    {}'.format(lib))
    ctx.exit()


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option('-v', '--version', is_flag=True, callback=print_version,
              expose_value=False, is_eager=True)
@click.pass_context
@click_skip_on_help
def cli(ctx):
    """
    Configure your YubiKey via the command line.
    """
    subcmd = next(c for c in COMMANDS if c.name == ctx.invoked_subcommand)
    transports = getattr(subcmd, 'transports', TRANSPORT.usb_transports())
    if transports:
        try:
            descriptors = list(get_descriptors())
        except usb.core.NoBackendError:
            ctx.fail('No PyUSB backend detected!')
        n_keys = len(descriptors)
        if n_keys == 0:
            ctx.fail('No YubiKey detected!')
        if n_keys > 1:
            ctx.fail('Multiple YubiKeys detected. Only a single YubiKey at a '
                     'time is supported.')
        descriptor = descriptors[0]
        if descriptor.mode.transports & transports:
            try:
                ctx.obj['dev'] = descriptor.open_device(transports)
                if not ctx.obj['dev']:  # Key should be there, busy?
                    raise FailedOpeningDeviceException()
            except FailedOpeningDeviceException:
                ctx.fail('Failed connecting to the YubiKey.')
        else:
            req = ', '.join((t.name for t in TRANSPORT if t & transports))
            click.echo("Command '{}' requires one of the following transports "
                       "to be enabled: '{}'.".format(subcmd.name, req))
            ctx.fail("Use 'ykman mode' to set the enabled connections.")


for cmd in COMMANDS:
    cli.add_command(cmd)


def main():
    try:
        cli(obj={})
    except ValueError as e:
        print('Error:', e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
