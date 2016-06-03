# PYTHON_ARGCOMPLETE_OK

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

from ykman import __version__
from ..util import TRANSPORT
from ..device import open_device, FailedOpeningDeviceException
from .gui import gui
from .info import info
from .mode import mode
from .slot import slot
from .opgp import openpgp
import time
import subprocess
import click


COMMANDS = (info, mode, slot, openpgp, gui)


def kill_scdaemon():
    try:
        # Works for Windows.
        from win32com.client import GetObject
        from win32api import OpenProcess, CloseHandle, TerminateProcess
        WMI = GetObject('winmgmts:')
        ps = WMI.InstancesOf('Win32_Process')
        for p in ps:
            if p.Properties_('Name').Value == 'scdaemon.exe':
                pid = p.Properties_('ProcessID').Value
                click.echo("Stopping scdaemon...")
                handle = OpenProcess(1, False, pid)
                TerminateProcess(handle, -1)
                CloseHandle(handle)
                time.sleep(0.1)
    except ImportError:
        # Works for Linux and OS X.
        pids = subprocess.check_output(
            "ps ax | grep scdaemon | grep -v grep | awk '{ print $1 }'",
            shell=True).strip()
        if pids:
            for pid in pids.split():
                click.echo("Stopping scdaemon...")
                subprocess.call(['kill', '-9', pid])
            time.sleep(0.1)


CLICK_CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help']
)


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('ykman version: {}'.format(__version__))
    ctx.exit()


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option('-v', '--version', is_flag=True, callback=print_version,
              expose_value=False, is_eager=True)
@click.pass_context
def cli(ctx):
    """
    Interface with a YubiKey via the command line.
    """
    dev = None
    subcmd = next(c for c in COMMANDS if c.name == ctx.invoked_subcommand)
    transports = getattr(subcmd, 'transports', sum(TRANSPORT))
    if transports:
        if TRANSPORT.CCID & transports:
            kill_scdaemon()
        try:
            dev = open_device(transports)
            if not dev:
                dev = open_device()
                if not dev:
                    ctx.fail('No YubiKey detected!')

                req = ', '.join((t.name for t in TRANSPORT
                                 if t & transports))
                if transports & dev.mode.transports != 0:
                    click.echo("Device wasn't accessible over one of "
                               "the required transports: {}"
                               .format(req))
                    click.echo("Perhaps the device is already in use?")
                else:
                    click.echo("Command '{}' requires one of the following "
                               "transports to be enabled: '{}'".format(
                                   subcmd.name, req))
                    click.echo("Use 'ykman mode' to set the enabled "
                               "transports.")
                ctx.exit(2)
        except FailedOpeningDeviceException:
            ctx.fail('Failed connecting to the YubiKey. Is it in use by '
                     'another process?')
    ctx.obj['dev'] = dev


for cmd in COMMANDS:
    cli.add_command(cmd)


def main():
    cli(obj={})


if __name__ == '__main__':
    main()
