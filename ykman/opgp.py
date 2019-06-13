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

import six
import struct
import logging
from .util import AID
from .driver_ccid import (APDUError, SW, GP_INS_SELECT)
from enum import Enum, IntEnum, unique
from binascii import b2a_hex, a2b_hex
from collections import namedtuple
from cryptography import x509
from cryptography.utils import int_to_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, SECP384R1, SECP521R1)

logger = logging.getLogger(__name__)

@unique
class KEY_SLOT(Enum):  # noqa: N801
    SIGNATURE = 'SIG'
    ENCRYPTION = 'ENC'
    AUTHENTICATION = 'AUT'
    ATTESTATION = 'ATT'

    def key_position(self):
        if self == KEY_SLOT.SIGNATURE:
            return 0x01
        if self == KEY_SLOT.ENCRYPTION:
            return 0x02
        if self == KEY_SLOT.AUTHENTICATION:
            return 0x03
        if self == KEY_SLOT.ATTESTATION:
            return 0x04

    def touch_position(self):
        if self == KEY_SLOT.SIGNATURE:
            return 0xd6
        if self == KEY_SLOT.ENCRYPTION:
            return 0xd7
        if self == KEY_SLOT.AUTHENTICATION:
            return 0xd8
        if self == KEY_SLOT.ATTESTATION:
            return 0xd9

    def cert_position(self):
        if self == KEY_SLOT.SIGNATURE:
            return 0x02
        if self == KEY_SLOT.ENCRYPTION:
            return 0x01
        if self == KEY_SLOT.AUTHENTICATION:
            return 0x00
        if self == KEY_SLOT.ATTESTATION:
            return 0x03


@unique
class TOUCH_MODE(IntEnum):  # noqa: N801
    OFF = 0x00
    ON = 0x01
    FIXED = 0x02
    CACHED = 0x03
    CACHED_FIXED = 0x04

    def __str__(self):
        if self == TOUCH_MODE.OFF:
            return 'Off'
        elif self == TOUCH_MODE.ON:
            return 'On'
        elif self == TOUCH_MODE.FIXED:
            return 'On (fixed)'
        elif self == TOUCH_MODE.CACHED:
            return 'Cached'
        elif self == TOUCH_MODE.CACHED_FIXED:
            return 'Cached (fixed)'


@unique
class TAG(IntEnum):  # noqa: N801
    CARDHOLDER_CERTIFICATE = 0x7f


@unique
class INS(IntEnum):  # noqa: N801
    GET_DATA = 0xca
    GET_VERSION = 0xf1
    SET_PIN_RETRIES = 0xf2
    VERIFY = 0x20
    TERMINATE = 0xe6
    ACTIVATE = 0x44
    PUT_DATA = 0xda
    GET_ATTESTATION = 0xfb
    SEND_REMAINING = 0xc0
    SELECT_DATA = 0xa5


PinRetries = namedtuple('PinRetries', ['pin', 'reset', 'admin'])


PW1 = 0x81
PW3 = 0x83
INVALID_PIN = b'\0'*8
TOUCH_METHOD_BUTTON = 0x20


class OpgpController(object):

    def __init__(self, driver):
        self._driver = driver
        # Use send_apdu instead of driver.select()
        # to get OpenPGP specific error handling.
        self.send_apdu(0, GP_INS_SELECT, 0x04, 0, AID.OPGP)
        self._version = self._read_version()

    @property
    def version(self):
        return self._version

    def send_apdu(self, cl, ins, p1, p2, data=b'', check=SW.OK):
        try:
            return self._driver.send_apdu(cl, ins, p1, p2, data, check)
        except APDUError as e:
            # If OpenPGP is in a terminated state send activate.
            if e.sw in (SW.NO_INPUT_DATA, SW.CONDITIONS_NOT_SATISFIED):
                self._driver.send_apdu(0, INS.ACTIVATE, 0, 0)
                return self._driver.send_apdu(cl, ins, p1, p2, data, check)
            raise

    def send_cmd(self, cl, ins, p1=0, p2=0, data=b'', check=SW.OK):
        while len(data) > 0xff:
            self._driver.send_apdu(0x10, ins, p1, p2, data[:0xff])
            data = data[0xff:]
        resp, sw = self._driver.send_apdu(0, ins, p1, p2, data, check=None)

        while (sw >> 8) == SW.MORE_DATA:
            more, sw = self._driver.send_apdu(
                0, INS.SEND_REMAINING, 0, 0, b'', check=None)
            resp += more

        if check is None:
            return resp, sw
        elif sw != check:
            raise APDUError(resp, sw)
        return resp

    def _read_version(self):
        bcd_hex = b2a_hex(self.send_apdu(0, INS.GET_VERSION, 0, 0))
        return tuple(int(bcd_hex[i:i+2]) for i in range(0, 6, 2))

    def get_remaining_pin_tries(self):
        data = self.send_apdu(0, INS.GET_DATA, 0, 0xc4)
        return PinRetries(*six.iterbytes(data[4:7]))

    def _block_pins(self):
        retries = self.get_remaining_pin_tries()

        for _ in range(retries.pin):
            self.send_apdu(0, INS.VERIFY, 0, PW1, INVALID_PIN, check=None)
        for _ in range(retries.admin):
            self.send_apdu(0, INS.VERIFY, 0, PW3, INVALID_PIN, check=None)

    def reset(self):
        if self.version < (1, 0, 6):
            raise ValueError('Resetting OpenPGP data requires version 1.0.6 or '
                             'later.')
        self._block_pins()
        self.send_apdu(0, INS.TERMINATE, 0, 0)
        self.send_apdu(0, INS.ACTIVATE, 0, 0)

    def _verify(self, pw, pin):
        try:
            pin = pin.encode('utf-8')
            self.send_apdu(0, INS.VERIFY, 0, pw, pin)
        except APDUError:
            pw_remaining = self.get_remaining_pin_tries()[pw-PW1]
            raise ValueError('Invalid PIN, {} tries remaining.'.format(
                pw_remaining))

    def get_touch(self, key_slot):
        if self.version < (4, 2, 0):
            raise ValueError('Touch policy is available on YubiKey 4 or later.')
        if self.version < (5, 2, 1) and key_slot == KEY_SLOT.ATTESTATION:
            raise ValueError('Attestation key not available on this device.')
        data = self.send_apdu(0, INS.GET_DATA, 0, key_slot.touch_position())
        return TOUCH_MODE(six.indexbytes(data, 0))

    def set_touch(self, key_slot, mode, admin_pin):
        if self.version < (4, 2, 0):
            raise ValueError('Touch policy is available on YubiKey 4 or later.')
        if self.version < (5, 2, 1) and mode in [
                    TOUCH_MODE.CACHED, TOUCH_MODE.CACHED_FIXED]:
            raise ValueError(
                    'Cached touch policies not available on this device.')
        self._verify(PW3, admin_pin)
        self.send_apdu(0, INS.PUT_DATA, 0, key_slot.touch_position(),
                       bytes(bytearray([mode, TOUCH_METHOD_BUTTON])))

    def set_pin_retries(self, pw1_tries, pw2_tries, pw3_tries, pin):
        if self.version < (1, 0, 7):  # For YubiKey NEO
            raise ValueError('Setting PIN retry counters requires version '
                             '1.0.7 or later.')
        if (4, 0, 0) <= self.version < (4, 3, 1):  # For YubiKey 4
            raise ValueError('Setting PIN retry counters requires version '
                             '4.3.1 or later.')
        self._verify(PW3, admin_pin)
        self.send_apdu(0, INS.SET_PIN_RETRIES, 0, 0,
                       bytes(bytearray([pw1_tries, pw2_tries, pw3_tries])))
