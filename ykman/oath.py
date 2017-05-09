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


import os
import hashlib
import struct
import hmac
import six
import time
from functools import total_ordering
from enum import IntEnum, unique
from .driver_ccid import APDUError, SW_OK
from .util import (
    AID, Tlv, parse_tlvs, time_challenge,
    format_code, parse_truncated, hmac_shorten_key)


@unique
class TAG(IntEnum):
    NAME = 0x71
    NAME_LIST = 0x72
    KEY = 0x73
    CHALLENGE = 0x74
    RESPONSE = 0x75
    TRUNCATED_RESPONSE = 0x76
    HOTP = 0x77
    PROPERTY = 0x78
    VERSION = 0x79
    IMF = 0x7a
    ALGORITHM = 0x7b
    TOUCH = 0x7c


@unique
class ALGO(IntEnum):
    SHA1 = 0x01
    SHA256 = 0x02


@unique
class OATH_TYPE(IntEnum):
    HOTP = 0x10
    TOTP = 0x20


@unique
class PROPERTIES(IntEnum):
    REQUIRE_TOUCH = 0x02


@unique
class INS(IntEnum):
    PUT = 0x01
    DELETE = 0x02
    SET_CODE = 0x03
    RESET = 0x04
    LIST = 0xa1
    CALCULATE = 0xa2
    VALIDATE = 0xa3
    CALCULATE_ALL = 0xa4
    SEND_REMAINING = 0xa5


@unique
class MASK(IntEnum):
    ALGO = 0x0f
    TYPE = 0xf0


@unique
class SW(IntEnum):
    NO_SPACE = 0x6a84
    COMMAND_ABORTED = 0x6f00
    MORE_DATA = 0x61
    INVALID_INSTRUCTION = 0x6d00


@total_ordering
class Credential(object):

    def __init__(
            self, name, code=None, oath_type='', touch=False, algo=None,
            expiration=None):
        self.name = name
        self.code = code
        self.oath_type = oath_type
        self.touch = touch
        self.algo = algo
        self.hidden = name.startswith('_hidden:')
        self.steam = name.startswith('Steam:')
        self.expiration = expiration

    def __lt__(self, other):
        return self.name.lower() < other.name.lower()

    def to_dict(self):
        return dict(self.__dict__)

    @staticmethod
    def from_dict(data):
        kwargs = dict(data)
        del kwargs['steam']
        del kwargs['hidden']
        return Credential(**kwargs)


class OathController(object):

    def __init__(self, driver):
        resp = driver.select(AID.OATH)
        tags = dict((x.tag, x.value) for x in parse_tlvs(resp))
        self._version = tuple(six.iterbytes(tags[TAG.VERSION]))
        self._id = tags[TAG.NAME]
        self._challenge = tags.get(TAG.CHALLENGE)
        self._driver = driver

    @property
    def version(self):
        return self._version

    @property
    def id(self):
        return self._id

    @property
    def locked(self):
        return self._challenge is not None

    @property
    def _426device(self):
        return (4, 2, 0) <= self.version <= (4, 2, 6)

    def send_apdu(self, ins, p1, p2, data=b''):
        resp, sw = self._driver.send_apdu(0, ins, p1, p2, data, check=None)
        while (sw >> 8) == SW.MORE_DATA:
            more, sw = self._driver.send_apdu(
                0, INS.SEND_REMAINING, 0, 0, b'', check=None)
            resp += more

        if sw != SW_OK:
            raise APDUError(resp, sw)

        return resp

    def reset(self):
        self.send_apdu(INS.RESET, 0xde, 0xad)

    def put(self, key, name, oath_type='totp', digits=6,
            algo='SHA1', counter=0, require_touch=False):

        oath_type = OATH_TYPE[oath_type.upper()].value
        algo = ALGO[algo].value

        data = bytearray(Tlv(TAG.NAME, name.encode('utf8')))

        key = hmac_shorten_key(key, ALGO(algo).name)
        key = bytearray([oath_type | algo, digits]) + key
        data += Tlv(TAG.KEY, key)

        properties = 0

        if require_touch:
            properties |= PROPERTIES.REQUIRE_TOUCH

        if properties:
            data.extend([TAG.PROPERTY, properties])

        if counter > 0:
            data += Tlv(TAG.IMF, struct.pack('>I', counter))

        self.send_apdu(INS.PUT, 0, 0, bytes(data))

    def list(self):
        resp = self.send_apdu(INS.LIST, 0, 0)
        while resp:
            length = six.indexbytes(resp, 1) - 1
            oath_type = MASK.TYPE & six.indexbytes(resp, 2)
            oath_type = OATH_TYPE(oath_type).name
            algo = MASK.ALGO & six.indexbytes(resp, 2)
            algo = ALGO(algo).name
            name = resp[3:3 + length].decode('utf-8')
            cred = Credential(name, oath_type=oath_type, algo=algo)
            yield cred
            resp = resp[3 + length:]

    def calculate(self, cred, timestamp=None):

        # The 4.2.0-4.2.6 firmwares have a known issue with credentials that
        # require touch: If this action is performed within 2 seconds of a
        # command resulting in a long response (over 54 bytes),
        # the command will hang. A workaround is to send an invalid command
        # (resulting in a short reply) prior to the "calculate" command.
        if self._426device and cred.touch:
            self._send_invalid_apdu()

        if timestamp is None:
            timestamp = int(time.time())
        challenge = time_challenge(timestamp)
        data = Tlv(TAG.NAME, cred.name.encode('utf-8')) + \
            Tlv(TAG.CHALLENGE, challenge)
        resp = self.send_apdu(INS.CALCULATE, 0, 0, data)
        resp = parse_tlvs(resp)[0].value
        # Manual dynamic truncation is required
        # for Steam entries, so let's do it for all.
        digits = six.indexbytes(resp, 0)
        resp = resp[1:]
        offset = resp[-1] & 0xF
        code = resp[offset:offset + 4]
        code = parse_truncated(code)
        cred.code = format_code(code, digits, steam=cred.steam)
        if cred.oath_type != 'hotp':
            cred.expiration = ((timestamp + 30) // 30) * 30
        return cred

    def delete(self, cred):
        data = Tlv(TAG.NAME, cred.name.encode('utf-8'))
        self.send_apdu(INS.DELETE, 0, 0, data)

    def calculate_all(self, timestamp=None):
        if timestamp is None:
            timestamp = int(time.time())
        data = Tlv(TAG.CHALLENGE, time_challenge(timestamp))
        resp = self.send_apdu(INS.CALCULATE_ALL, 0, 0x01, data)
        tlvs = parse_tlvs(resp)
        while tlvs:
            name = tlvs.pop(0).value.decode('utf-8')
            resp = tlvs.pop(0)
            digits = six.indexbytes(resp.value, 0)
            cred = Credential(name)
            if resp.tag == TAG.TRUNCATED_RESPONSE:
                cred.oath_type = 'totp'
                if cred.steam:
                    cred = self.calculate(cred, timestamp)
                else:
                    code = parse_truncated(resp.value[1:])
                    cred.code = format_code(code, digits)
                    cred.expiration = ((timestamp + 30) // 30) * 30
            elif resp.tag == TAG.HOTP:
                cred.oath_type = 'hotp'
            elif resp.tag == TAG.TOUCH:
                cred.touch = True
            yield cred

    def set_password(self, key):
        keydata = bytearray([OATH_TYPE.TOTP | ALGO.SHA1]) + key
        challenge = os.urandom(8)
        response = hmac.new(key, challenge, hashlib.sha1).digest()
        data = Tlv(TAG.KEY, keydata) + Tlv(TAG.CHALLENGE, challenge) + Tlv(
            TAG.RESPONSE, response)
        self.send_apdu(INS.SET_CODE, 0, 0, data)

    def clear_password(self):
        self.send_apdu(INS.SET_CODE, 0, 0, Tlv(TAG.KEY, b''))

    def validate(self, key):
        response = hmac.new(key, self._challenge, hashlib.sha1).digest()
        challenge = os.urandom(8)
        verification = hmac.new(key, challenge, hashlib.sha1).digest()
        data = Tlv(TAG.RESPONSE, response) + Tlv(TAG.CHALLENGE, challenge)
        resp = self.send_apdu(INS.VALIDATE, 0, 0, data)
        if parse_tlvs(resp)[0].value != verification:
            raise ValueError(
                'Response from validation does not match verification!')
        self._challenge = None

    def _send_invalid_apdu(self):
        self._driver.send_apdu(0, 0, 0, 0, '', check=SW.INVALID_INSTRUCTION)
