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

import argparse
import sys
from ykman import __version__
from ..device import open_device, FailedOpeningDeviceException
from .gui import GuiCommand
from .info import InfoCommand
from .mode import ModeCommand
from .slot import SlotCommand


class CliRunner(object):

    def __init__(self):
        self._cmds = {}
        self._parser = self._init_parser()

    def _init_parser(self):
        parser = argparse.ArgumentParser(
            description="Interface with a YubiKey via the command line",
            add_help=True
        )
        parser.add_argument('-v', '--version', action='version',
                            version='%(prog)s version ' + __version__)

        subparser = parser.add_subparsers(dest='command', help='subcommands')
        self._add_command(subparser, InfoCommand)
        self._add_command(subparser, GuiCommand)
        self._add_command(subparser, ModeCommand)
        self._add_command(subparser, SlotCommand)

        return parser

    def _add_command(self, subparser, Cmd):
        self._cmds[Cmd.name] = Cmd(subparser.add_parser(Cmd.name,
                                                        help=Cmd.help))

    def _subcmd_names(self):
        for a in self._parser._subparsers._actions:
            if isinstance(a, argparse._SubParsersAction):
                for name in a._name_parser_map.keys():
                    yield name

    def run(self):
        subcmds = list(self._subcmd_names()) + \
            ['-h', '--help', '-v', '--version']
        if not bool(set(sys.argv[1:]) & set(subcmds)):
            sys.argv.insert(1, subcmds[0])

        try:  # If argcomplete is available, use it.
            import argcomplete
            argcomplete.autocomplete(self._parser)
        except ImportError:
            pass

        args = self._parser.parse_args()
        try:
            dev = open_device()
        except FailedOpeningDeviceException:
            print 'Failed connecting to the YubiKey. ' +\
                'Is it in use by another process?'
            return 2
        status = self._cmds[args.command].run(args, dev)
        if status is None:
            status = 0
        return status


def main():
    runner = CliRunner()
    sys.exit(runner.run())


if __name__ == '__main__':
    main()
