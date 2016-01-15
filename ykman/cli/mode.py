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

import re
import sys
import argparse

from ..util import Mode


def _parse_mode_string(mode):
    found = set()
    parts = set(filter(None, re.split(r'[+ ,]+', mode.lower())))
    if len(parts) <= 3:
        for p in parts:
            for available in ['otp', 'u2f', 'ccid']:
                if available.startswith(p):
                    found.add(available)
                    break
            else:
                raise ValueError('Invalid mode string: %s' % mode)
    if len(found) > 0:
        return Mode('otp' in found, 'u2f' in found, 'ccid' in found)
    raise ValueError('Invalid mode string: %s' % mode)


class ModeAction(argparse.Action):

    def __call__(self, parser, args, values, option_string=None):
        if values is not None:
            try:  # Numeric mode
                mode = Mode.from_code(int(values))
            except ValueError:  # Text mode
                mode = _parse_mode_string(values)
            setattr(args, self.dest, mode)


class TouchEjectAction(argparse.Action):

    def __call__(self, parser, args, values, option_string=None):
        if args.mode != Mode(ccid=True):
            parser.error('--touch-eject can only be used when setting CCID-only'
                         ' mode')

        if values is None:  # Arg set without argument.
            values = 0
        setattr(args, self.dest, values)


class ModeCommand(object):
    name = 'mode'
    help = 'get and set the mode of the YubiKey'

    def __init__(self, parser):
        parser.add_argument('mode', action=ModeAction, nargs='?',
                            help='new mode to set')
        parser.add_argument('-f', '--force', action='store_true',
                            help='don\'t prompt for confirmation')
        parser.add_argument('--touch-eject', nargs='?', action=TouchEjectAction,
                            type=int, help='''when set, the button on the
                            YubiKey will eject/insert the card (CCID mode only)

                            Optionally give a timeout in seconds to auto-eject
                            the card after a period of inactivity.
                            ''')
        parser.add_argument('--challenge-response-timeout', type=int,
                            default=15, help='''set the timeout for
                            challenge-response in seconds
                            ''')

    def run(self, args, dev):
        if args.mode is not None:
            if not args.force:
                if args.mode == dev.mode:
                    print 'Mode is already %s, nothing to do...' % args.mode
                    return 0
                else:
                    print 'Set mode of YubiKey to %s? (y/n) [n]' % args.mode
                    read = sys.stdin.readline().strip()
                    if read.lower() not in ['y', 'yes']:
                        print 'Aborted.'
                        return 1

            dev.set_mode(args.mode,
                            args.challenge_response_timeout,
                            args.touch_eject)
            print 'Mode set! You must remove and re-insert your YubiKey ' +\
                'for this change to take effect.'
        elif dev is None:
            print 'no YubiKey detected!'
        else:
            print 'mode is:', dev.mode
