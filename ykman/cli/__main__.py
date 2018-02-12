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
from ..util import TRANSPORT, Mode, Cve201715361VulnerableError
from ..native.pyusb import get_usb_backend_version
from ..driver_otp import libversion as ykpers_version
from ..driver_u2f import libversion as u2fhost_version
from ..descriptor import (get_descriptors, list_drivers, open_device,
                          FailedOpeningDeviceException)
from .util import click_skip_on_help
from .info import info
from .mode import mode
from .slot import slot
from .opgp import openpgp
from .oath import oath
from .piv import piv
import ykman.logging_setup
import usb.core
import click
import logging
import sys


logger = logging.getLogger(__name__)


CLICK_CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help'],
    max_content_width=999
)


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('YubiKey Manager (ykman) version: {}'.format(__version__))
    libs = []
    libs.append('libykpers ' + ('.'.join('%d' % d for d in ykpers_version)
                                if ykpers_version is not None
                                else 'not found!'))
    libs.append('libu2f-host ' + ('.'.join('%d' % d for d in u2fhost_version)
                                  if u2fhost_version is not None
                                  else 'not found!'))
    usb_lib = get_usb_backend_version()
    libs.append(usb_lib or '<pyusb backend missing>')
    click.echo('Libraries:')
    for lib in libs:
        click.echo('    {}'.format(lib))
    ctx.exit()


def _disabled_transport(ctx, transports, cmd_name):
    req = ', '.join((t.name for t in TRANSPORT if t & transports))
    click.echo("Command '{}' requires one of the following transports "
               "to be enabled: '{}'.".format(cmd_name, req))
    ctx.fail("Use 'ykman mode' to set the enabled connections.")


def _run_cmd_for_serial(ctx, cmd, transports, serial):
    try:
        ctx.obj['dev'] = open_device(transports, serial=serial)
    except FailedOpeningDeviceException:
        try:  # Retry, any transport
            dev = open_device(serial=serial)
            if not dev.mode.transports & transports:
                if dev.capabilities & transports:
                    _disabled_transport(ctx, transports, cmd)
                else:
                    ctx.fail("Command '{}' is not supported by this device."
                             .format(cmd))
        except FailedOpeningDeviceException:
            ctx.fail('Failed connecting to a YubiKey with serial: {}'
                     .format(serial))


def _run_cmd_for_single(ctx, cmd, transports):
    try:
        descriptors = get_descriptors()
    except usb.core.NoBackendError:
        ctx.fail('No PyUSB backend detected!')
    n_keys = len(descriptors)
    if n_keys == 0:
        ctx.fail('No YubiKey detected!')
    if n_keys > 1:
        ctx.fail('Multiple YubiKeys detected. Use --device SERIAL to specify '
                 'which one to use.')
    descriptor = descriptors[0]
    if descriptor.mode.transports & transports:
        try:
            ctx.obj['dev'] = descriptor.open_device(transports)
        except FailedOpeningDeviceException:
            ctx.fail('Failed connecting to the YubiKey.')
    else:
        _disabled_transport(ctx, transports, cmd)


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option('-v', '--version', is_flag=True, callback=print_version,
              expose_value=False, is_eager=True)
@click.option('-d', '--device', type=int, metavar='SERIAL')
@click.option('-l', '--log-level', default=None,
              type=click.Choice(ykman.logging_setup.LOG_LEVEL_NAMES),
              help='Enable logging at given verbosity level',
              )
@click.option('--log-file', default=None,
              type=str, metavar='FILE',
              help='Write logs to the given FILE instead of standard error; '
                   'ignored unless --log-level is also set',
              )
@click.pass_context
@click_skip_on_help
def cli(ctx, device, log_level, log_file):
    """
    Configure your YubiKey via the command line.
    """

    if log_level:
        ykman.logging_setup.setup(log_level, log_file=log_file)

    subcmd = next(c for c in COMMANDS if c.name == ctx.invoked_subcommand)
    if subcmd == list_keys:
        return

    transports = getattr(subcmd, 'transports', TRANSPORT.usb_transports())
    if transports:
        if device is not None:
            _run_cmd_for_serial(ctx, subcmd.name, transports, device)
        else:
            _run_cmd_for_single(ctx, subcmd.name, transports)


@cli.command('list')
@click.option('-s', '--serials', is_flag=True, help='Output only serial '
              'numbers, one per line.')
@click.pass_context
def list_keys(ctx, serials):
    """
    List connected YubiKeys.
    """
    descriptors = get_descriptors()
    handled = set()
    for drv in list_drivers():
        serial = drv.serial
        if serial not in handled:
            handled.add(serial)
            matches = [d for d in descriptors if d.pid == drv.pid]
            if len(matches) > 0:
                d = matches[0]
                descriptors.remove(d)
                if serials:
                    click.echo(serial)
                else:
                    click.echo('{} [{}] Serial: {}'.format(
                        drv.key_type.value,
                        Mode(drv.transports),
                        serial or 'Not available')
                    )
        del drv


COMMANDS = (list_keys, info, mode, slot, openpgp, oath, piv)


for cmd in COMMANDS:
    cli.add_command(cmd)


def main():
    try:
        cli(obj={})
    except ValueError as e:
        logger.error('Error', exc_info=e)
        print('Error:', e)
        return 1

    except Cve201715361VulnerableError as err:
        logger.error('Error', exc_info=err)
        print('Error:', err)
        return 2


if __name__ == '__main__':
    sys.exit(main())
