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


from .driver_ccid import OPGP_AID, SW_OK
from ykman.yubicommon.compat import byte2int, int2byte
from enum import IntEnum
from binascii import b2a_hex


class KEY_SLOT(IntEnum):
    SIGN = 0xd6
    ENCRYPT = 0xd7
    AUTHENTICATE = 0xd8


class TOUCH_MODE(IntEnum):
    OFF = 0x00
    ON = 0x01
    ON_FIXED = 0x02


class INS(IntEnum):
    SELECT = 0xa4
    GET_DATA = 0xca
    GET_VERSION = 0xf1
    SET_PIN_RETRIES = 0xf2
    VERIFY = 0x20
    TERMINATE = 0xe6
    ACTIVATE = 0x44
    PUT_DATA = 0xda


PW1 = 0x81
PW3 = 0x83
INVALID_PIN = b'\0'*8


class OpgpController(object):

    def __init__(self, driver):
        self._driver = driver
        self.select()
        self._version = self._read_version()

    @property
    def version(self):
        return self._version

    def send_apdu(self, cl, ins, p1, p2, data=b''):
        return self._driver.send_apdu(cl, ins, p1, p2, data)

    def _read_version(self):
        bcd_hex = b2a_hex(self.send_apdu(0, INS.GET_VERSION, 0, 0)[0])
        return tuple(int(bcd_hex[i:i+2]) for i in range(0, 6, 2))

    def select(self):
        _, sw = self.send_apdu(0, INS.SELECT, 0x04, 0, OPGP_AID)
        if sw != SW_OK:
            raise Exception('Failure selecting applet!')

    def _get_pin_tries(self):
        data, sw = self.send_apdu(0, INS.GET_DATA, 0, 0xc4)
        if sw != SW_OK:
            raise Exception('Failue reading PIN retries!')
        return tuple(byte2int(x) for x in data[4:7])

    def _block_pins(self):
        pw1_tries, _, pw3_tries = self._get_pin_tries()

        for _ in range(pw1_tries):
            _, sw = self.send_apdu(0, INS.VERIFY, 0, PW1, INVALID_PIN)
        for _ in range(pw3_tries):
            _, sw = self.send_apdu(0, INS.VERIFY, 0, PW3, INVALID_PIN)

    def reset(self):
        self._block_pins()
        _, sw = self.send_apdu(0, INS.TERMINATE, 0, 0)
        if sw != SW_OK:
            raise Exception('Failure resetting OpenPGP!')
        _, sw = self.send_apdu(0, INS.ACTIVATE, 0, 0)
        if sw != SW_OK:
            raise Exception('Failed initializing OpenPGP!')

    def get_touch(self, key_slot):
        data, sw = self.send_apdu(0, INS.GET_DATA, 0, key_slot)
        if sw == SW_OK:
            return TOUCH_MODE(byte2int(data[0]))
        else:
            raise Exception('Failure reading touch mode for key {.name}'
                            .format(key_slot))
        return data

    def _verify(self, pw, pin):
        _, sw = self.send_apdu(0, INS.VERIFY, 0, pw, pin)
        if sw != SW_OK:
            pw_remaining = self._get_pin_tries()[pw-PW1]
            raise ValueError('Invalid PIN, {} tries remaining.'.format(
                pw_remaining))

    def set_touch(self, key_slot, mode, pin):
        self._verify(PW3, pin)
        _, sw = self.send_apdu(0, INS.PUT_DATA, 0, key_slot,
                               int2byte(mode) + b'\x20')
        if sw != SW_OK:
            raise Exception('Failure setting touch policy!')

    def set_pin_retries(self, pw1_tries, pw2_tries, pw3_tries, pin):
        self._verify(PW3, pin)
        _, sw = self.send_apdu(0, INS.SET_PIN_RETRIES, 0, 0,
                               int2byte(pw1_tries) +
                               int2byte(pw2_tries) +
                               int2byte(pw3_tries))
        if sw != SW_OK:
            raise Exception('Failure setting PIN retries!')
