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

from ykman.yubicommon.cli import CliCommand, Argument
from .util import confirm
from ..util import TRANSPORT, modhex_decode, modhex_encode

import os
import re
import struct
from base64 import b32decode
from binascii import a2b_hex


def int_6_or_8(val):
    int_val = int(val)
    if int_val == 6:
        return False
    elif int_val == 8:
        return True
    else:
        raise ValueError('must be 6 or 8')


def parse_key(val):
    val = val.upper()
    if re.match(r'^([0-9A-F]{2})+$', val):  # hex
        return a2b_hex(val)
    else:
        # Key should be b32 encoded
        val += '=' * (-len(val) % 8)  # Support unpadded
        try:
            return b32decode(val)
        except TypeError as e:
            raise ValueError('{}'.format(e))


class SlotCommand(CliCommand):
    """
    Manage YubiKey OTP slots.

    Usage:
    ykman slot
    ykman slot swap [-f]
    ykman slot (1 | 2) delete [-f]
    ykman slot (1 | 2) otp <key> [--public-id FIXED] [--private-id UID]
                                 [-f] [--no-enter]
    ykman slot (1 | 2) static <password> [-f] [--no-enter]
    ykman slot (1 | 2) chalresp [<key>] [-f] [--require-touch]
    ykman slot (1 | 2) hotp <key> [-f] [--no-enter] [--digits N] [--imf IMF]

    <key> should be given as a hex or base32 encoded string
    <private-id> should be given as a 6 byte (12 character) hex value

    Options:
        -h, --help         show this help message
        -f, --force        don't ask for confirmation for actions
        --no-enter         don't trigger the Enter key after the password
        --public-id FIXED  fixed part of the OTP, defaults to the devices serial
                           number in modhex
        --private-id UID   optional private identifier of the OTP credential
        --require-touch    require physical button press to generate response
        --digits N         number of digits to output for HOTP [default: 6]
        --imf IMF          initial moving factor for HOTP [default: 0]
    """

    name = 'slot'
    transports = TRANSPORT.OTP

    slot = Argument(('1', '2'), int)
    action = Argument(('swap', 'delete', 'otp', 'static', 'chalresp', 'hotp'),
                      default='info')
    force = Argument('--force', bool)
    no_enter = Argument('--no-enter', bool)
    private_id = Argument('--private-id', a2b_hex, b'\0' * 6)
    public_id = Argument('--public-id', modhex_decode)
    require_touch = Argument('--require-touch', bool)
    static_password = Argument('<password>')
    key = Argument('<key>', parse_key)
    hotp8 = Argument('--digits', int_6_or_8)
    imf = Argument('--imf', int)

    def __call__(self, dev):
        return getattr(self, '_{}_action'.format(self.action))(dev)

    def _info_action(self, dev):
        print(dev.device_name)
        slot1, slot2 = dev.driver.slot_status
        print('Slot 1:', slot1 and 'programmed' or 'empty')
        print('Slot 2:', slot2 and 'programmed' or 'empty')

    def _confirm(self, message):
        if not self.force:
            confirm(message)

    def _swap_action(self, dev):
        self.force or confirm('Swap slots of YubiKey?')
        print('Swapping slots...')
        dev.driver.swap_slots()
        print('Success!')

    def _delete_action(self, dev):
        self.force or confirm('Delete slot {} of YubiKey?'.format(self.slot))
        print('Deleting slot: {}...'.format(self.slot))
        dev.driver.zap_slot(self.slot)
        print('Success!')

    def _otp_action(self, dev):
        if self.public_id is None:
            if dev.serial is None:
                raise ValueError('serial number not set, '
                                 'public-id must be provided')
            self.public_id = b'\x77\x77' + struct.pack(b'>I', dev.serial)
            print('Using serial as public ID: {}'
                  .format(modhex_encode(self.public_id)))
        self.force or confirm('Program an OTP credential in slot {}?'
                              .format(self.slot))
        dev.driver.program_otp(self.slot, self.key, self.public_id,
                               self.private_id, not self.no_enter)
        print('Success!')

    def _static_action(self, dev):
        self.force or confirm('Program a static password in slot {}?'
                              .format(self.slot))
        print('Setting static password in slot {}...'.format(self.slot))
        dev.driver.program_static(self.slot, self.static_password,
                                  not self.no_enter)
        print('Success!')

    def _chalresp_action(self, dev):
        if not self.key:
            print('Using a randomly generated key.')
            self.key = os.urandom(20)

        self.force or confirm(
            'Program a challenge-response credential in slot {}?'
            .format(self.slot))

        print('Programming challenge-response in slot {}...'.format(self.slot))
        dev.driver.program_chalresp(self.slot, self.key, self.require_touch)
        print('Success!')

    def _hotp_action(self, dev):
        self.force or confirm('Program a HOTP credential in slot {}?'
                              .format(self.slot))

        print('Programming HOTP credential in slot {}...'.format(self.slot))
        dev.driver.program_hotp(self.slot, self.key, self.imf, self.hotp8,
                                not self.no_enter)
        print('Success!')
