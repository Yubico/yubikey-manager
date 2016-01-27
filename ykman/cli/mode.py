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

from __future__ import print_function

import re

from ykman.yubicommon.cli import CliCommand, Argument
from .util import confirm
from ..util import Mode, TRANSPORT


def _parse_mode_string(mode):
    try:
        mode_int = int(mode)
        return Mode.from_code(mode_int)
    except IndexError:
        raise ValueError('Invalid mode: {}'.format(mode_int))
    except ValueError:
        pass  # Not a numeric mode, parse string

    found = set()
    parts = set(filter(None, re.split(r'[+ ,]+', mode.upper())))
    if len(parts) <= 3:
        for p in parts:
            for available in TRANSPORT:
                if available.name.startswith(p):
                    found.add(available)
                    break
            else:
                raise ValueError('Invalid mode string: {}'.format(mode))
    if len(found) > 0:
        return Mode(sum(found))
    raise ValueError('Invalid mode string: {}'.format(mode))


class ModeCommand(CliCommand):
    """
    Manage YubiKey transport mode.

    Usage:
    ykman mode
    ykman mode <mode> [-f] [--touch-eject [TIMEOUT]]
                      [--challenge-response-timeout TIMEOUT]

    Options:
        -h, --help      show this help message
        -f, --force     don't ask for confirmation for actions
                        when set, the button on the YubiKey will eject/insert
                        the card (CCID mode only) Optionally give a timeout in
                        seconds to auto-eject the card after a period of
                        inactivity.
        --touch-eject  [TIMEOUT]
                        CCID mode only. When set, the button on the YubiKey will
                        eject/insert the card. Optionally provide a TIMEOUT
                        value to cause the card to automatically eject after a
                        period of inactivity.
        --challenge-response-timeout TIMEOUT
                        set the timeout for challenge-response in seconds
    """

    name = 'mode'

    force = Argument('--force', bool)
    mode = Argument('<mode>', _parse_mode_string)
    touch_eject = Argument('--touch-eject', bool)
    autoeject_timeout = Argument('TIMEOUT', int)
    cr_timeout = Argument('--challenge-response-timeout', int, 0)

    def __call__(self, dev):
        if self.mode is not None:
            autoeject = self.autoeject_timeout if self.touch_eject else None
            if self.mode.transports != TRANSPORT.CCID:
                autoeject = None
                if self.touch_eject:
                    print('--touch-eject can only be used when setting'
                          'CCID-only mode')
                    return 1

            if not self.force:
                if self.mode == dev.mode:
                    print('Mode is already {}, nothing to do...'
                          .format(self.mode))
                    return 0
                elif not dev.has_mode(self.mode):
                    print('Mode {} is not supported on this device!'
                          .format(self.mode))
                    print('Use --force to attempt to set it anyway.')
                    return 1
                confirm('Set mode of YubiKey to {}?'.format(self.mode))

            dev.set_mode(self.mode, self.cr_timeout, autoeject)
            print('Mode set! You must remove and re-insert your YubiKey for '
                  'this change to take effect.')
        else:
            print('Current mode is:', dev.mode)
            supported = ', '.join(t.name for t in TRANSPORT
                                  if dev.capabilities & t)
            print('Supported transports are:', supported)
