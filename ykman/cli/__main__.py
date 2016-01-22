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

import sys
from ykman import __version__
from ykman.yubicommon.cli import CliCommand, Argument
from ..device import open_device, FailedOpeningDeviceException
from .gui import GuiCommand
from .info import InfoCommand
from .mode import ModeCommand
from .slot import SlotCommand


CMDS = (InfoCommand, GuiCommand, ModeCommand, SlotCommand)


def _get_subcommand(cmd_name):
    for Cmd in CMDS:
        if Cmd.name == cmd_name:
            return Cmd
    raise ValueError('Unknown command: {}'.format(cmd_name))


class MainCommand(CliCommand):
    """
    Interface with a YubiKey via the command line

    Usage:
        ykman [options] [<command> [<args>...]]

    Commands:
        info    displays information about the connected YubiKey
        gui     launches the graphical interface
        mode    show or set the current transport mode
        slot    show or modify YubiKey OTP slots

    Use 'ykman <command> -h' for additional help with a command.

    Options:
        -h, --help      show this help message
        -v, --version   show the program's version number
    """

    cmd = Argument('<command>', _get_subcommand, default=InfoCommand)
    sub_argv = Argument('<args>')

    def __init__(self, *args, **kwargs):
        kwargs['options_first'] = True
        super(MainCommand, self).__init__(*args, **kwargs)

    def __call__(self):
        subcmd = self.cmd(argv=[self.cmd.name] + self.sub_argv)
        try:
            dev = open_device()
        except FailedOpeningDeviceException:
            print 'Failed connecting to the YubiKey. ' +\
                'Is it in use by another process?'
            return 2
        status = subcmd(dev)
        return status if status is not None else 0


def main():
    cmd = MainCommand(version='%(prog)s version ' + __version__)
    sys.exit(cmd())


if __name__ == '__main__':
    main()
