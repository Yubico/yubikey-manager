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


class ModeCommand(object):
    name = 'mode'
    help = 'Get and set the mode of the YubiKey'

    def __init__(self, parser):
        parser.add_argument('mode', nargs='?', help='new mode to set')

    def run(self, args, dev):
        if args.mode is not None:
            try:  # Numeric mode:
                mode = Mode.from_code(int(args.mode))
            except ValueError:  # Text mode
                mode = _parse_mode_string(args.mode)
            print "setting mode %s" % mode
        elif dev is None:
            print "no YubiKey detected!"
        else:
            print "mode is:", dev.mode
