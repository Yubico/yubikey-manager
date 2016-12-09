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


import hashlib
import struct
from enum import IntEnum
from ykman.yubicommon.compat import byte2int, int2byte
from .driver_ccid import APDUError, OATH_AID, SW_OK
from .util import tlv


class TAG(IntEnum):
    NAME = 0x71
    KEY = 0x73
    PROPERTY = 0x78
    NAME_LIST = 0x72
    IMF = 0x7a


class ALGO(IntEnum):
    SHA1 = 0x01
    SHA256 = 0x02


class OATH_TYPE(IntEnum):
    HOTP = 0x10
    TOTP = 0x20


class PROPERTIES(IntEnum):
    REQUIRE_TOUCH = 0x02


class INS(IntEnum):
    SELECT = 0xa4
    PUT = 0x01
    RESET = 0x04
    LIST = 0xa1
    SEND_REMAINING = 0xa5


class MASK(IntEnum):
    TYPE = 0xf0
    ALGO = 0x0f


class SW(IntEnum):
    NO_SPACE = 0x6a84
    COMMAND_ABORTED = 0x6f00
    MORE_DATA = 0x61


class OathController(object):

    def __init__(self, driver):
        self._driver = driver
        self.select()
        self._version = self._read_version()

    @property
    def version(self):
        return self._version

    def send_apdu(self, cl, ins, p1, p2, data=b''):
        resp, sw = self._driver.send_apdu(cl, ins, p1, p2, data, check=None)
        while (sw >> 8) == SW.MORE_DATA:
            more, sw = self._driver.send_apdu(
                0, INS.SEND_REMAINING, 0, 0, '', check=None)
            resp += more

        if sw != SW_OK:
            raise APDUError(resp, sw)

        return resp

    def _read_version(self):
        data = self.send_apdu(0, INS.SELECT, 0x04, 0, OATH_AID)
        return tuple(byte2int(x) for x in data[2:5])

    def select(self):
        self.send_apdu(0, INS.SELECT, 0x04, 0, OATH_AID)

    def reset(self):
        self.send_apdu(0, INS.RESET, 0xde, 0xad)

    def put(self, key, name, oath_type='totp', digits=6,
            algo='SHA1', counter=0, require_touch=False):

        oath_type = OATH_TYPE[oath_type.upper()].value
        algo = ALGO[algo].value

        key = hmac_shorten_key(key, algo)
        key = int2byte(oath_type | algo) + int2byte(digits) + key

        data = tlv(TAG.NAME, name.encode('utf8')) + tlv(TAG.KEY, key)

        properties = 0

        if require_touch:
            properties |= PROPERTIES.REQUIRE_TOUCH

        if properties:
            data += int2byte(TAG.PROPERTY) + int2byte(properties)

        if counter > 0:
            data += tlv(TAG.IMF, struct.pack('>I', counter))

        self.send_apdu(0, INS.PUT, 0, 0, data)

    def list(self):

        resp = self.send_apdu(0, INS.LIST, 0, 0)

        while resp:
            assert byte2int(resp[0]) == TAG.NAME_LIST
            length = byte2int(resp[1]) - 1
            oath_type = (MASK.TYPE & byte2int(resp[2]))
            algo = (MASK.ALGO & byte2int(resp[2]))
            name = resp[3:3 + length]
            yield (
                name.decode('utf-8'),
                OATH_TYPE(oath_type).name,
                ALGO(algo).name)
            resp = resp[3 + length:]


def hmac_shorten_key(key, algo):
    if algo == ALGO.SHA1:
        h = hashlib.sha1()
    elif algo == ALGO.SHA256:
        h = hashlib.sha256()
    else:
        raise ValueError('Unsupported algorithm!')
    if len(key) > h.block_size:
        key = h.update(key).digest()
    return key
