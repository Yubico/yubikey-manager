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

import os
import re
import struct
import six
import time
from base64 import b64encode
from functools import total_ordering
from enum import IntEnum, unique
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend
from six.moves.urllib.parse import unquote, urlparse, parse_qs
from .driver_ccid import APDUError, SW_OK
from .util import (
    AID, Tlv, parse_tlvs, time_challenge, parse_b32_key,
    format_code, parse_truncated, hmac_shorten_key)


HMAC_MINIMUM_KEY_SIZE = 14


@unique
class TAG(IntEnum):
    NAME = 0x71
    NAME_LIST = 0x72
    KEY = 0x73
    CHALLENGE = 0x74
    RESPONSE = 0x75
    TRUNCATED_RESPONSE = 0x76
    NO_RESPONSE = 0x77
    PROPERTY = 0x78
    VERSION = 0x79
    IMF = 0x7a
    ALGORITHM = 0x7b
    TOUCH = 0x7c


@unique
class ALGO(IntEnum):
    SHA1 = 0x01
    SHA256 = 0x02
    SHA512 = 0x03


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


class CredentialData(object):

    def __init__(self, secret, issuer, name, oath_type=OATH_TYPE.TOTP,
                 algorithm=ALGO.SHA1, digits=6, period=30, counter=0,
                 touch=False):
        self.secret = secret
        self.issuer = issuer
        self.name = name
        self.oath_type = oath_type
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.counter = counter
        self.touch = touch

    @classmethod
    def from_uri(cls, uri):
        parsed = urlparse(uri.strip())
        if parsed.scheme != 'otpauth':
            raise ValueError('Invalid URI scheme')

        params = dict((k, v[0]) for k, v in parse_qs(parsed.query).items())
        params['secret'] = parse_b32_key(params['secret'])
        params['algorithm'] = ALGO[params.get('algorithm', 'SHA1').upper()]
        issuer = None
        name = unquote(parsed.path)[1:]  # Unquote and strip leading /
        if ':' in name:
            issuer, name = name.split(':', 1)
        params['issuer'] = params.get('issuer', issuer)
        params['name'] = name
        params['oath_type'] = OATH_TYPE[parsed.hostname.upper()]
        params['digits'] = int(params.get('digits', 6))
        params['period'] = int(params.get('period', 30))
        params['counter'] = int(params.get('counter', 0))
        return cls(**params)

    def make_key(self):
        key = self.name
        if self.issuer:
            key = '%s:%s' % (self.issuer, key)
        if self.oath_type == OATH_TYPE.TOTP and self.period != 30:
            key = '%d/%s' % (self.period, key)
        return key.encode('utf-8')


@total_ordering
class Credential(object):

    def __init__(self, key, oath_type=OATH_TYPE.TOTP, touch=False):
        self.key = key
        self.oath_type = oath_type
        self.touch = touch
        self.issuer, self.name, period = Credential.parse_key(key)
        self.period = period if oath_type == OATH_TYPE.TOTP else None

    def __lt__(self, other):
        a = ((self.issuer or self.name).lower(), self.name.lower())
        b = ((other.issuer or other.name).lower(), other.name.lower())
        return a < b

    @property
    def is_steam(self):
        return self.issuer == 'Steam'

    @property
    def is_hidden(self):
        return self.issuer == '_hidden'

    @property
    def printable_key(self):
        return self.key.decode('utf-8')

    @staticmethod
    def parse_key(data):
        if re.match(br'^\d+/', data):
            period, data = data.split(b'/', 1)
            period = int(period)
        else:
            period = 30

        if b':' in data:
            issuer, data = data.split(b':', 1)
            issuer = issuer.decode('utf-8')
        else:
            issuer = None
        return issuer, data.decode('utf-8'), period


def _derive_key(salt, passphrase):
    kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())
    return kdf.derive(passphrase.encode('utf-8'))


def _get_device_id(device_salt):
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(device_salt)
    d = h.finalize()[:16]
    return b64encode(d).replace(b'=', b'').decode()


class Code(object):

    def __init__(self, value, valid_from, valid_to):
        self.value = value
        self.valid_from = valid_from
        self.valid_to = valid_to

    def __str__(self):
        return self.value


class OathController(object):

    def __init__(self, driver):
        resp = driver.select(AID.OATH)
        tags = dict((x.tag, x.value) for x in parse_tlvs(resp))
        self._version = tuple(six.iterbytes(tags[TAG.VERSION]))
        self._salt = tags[TAG.NAME]
        self._id = _get_device_id(self._salt)
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
    def is_in_fips_mode(self):
        return self.locked

    @property
    def _426device(self):
        return (4, 2, 0) <= self.version <= (4, 2, 6)

    def derive_key(self, password):
        return _derive_key(self._salt, password)

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
        resp = self._driver.select(AID.OATH)
        tags = dict((x.tag, x.value) for x in parse_tlvs(resp))
        self._salt = tags[TAG.NAME]
        self._id = _get_device_id(self._salt)

    def put(self, credential_data):
        d = credential_data
        key = d.make_key()
        secret_header = bytearray([d.oath_type | d.algorithm, d.digits])
        secret = hmac_shorten_key(d.secret, d.algorithm.name)
        secret = secret.ljust(HMAC_MINIMUM_KEY_SIZE, b'\x00')
        data = Tlv(TAG.NAME, key) + Tlv(TAG.KEY, secret_header + secret)
        properties = 0

        if d.touch:
            properties |= PROPERTIES.REQUIRE_TOUCH

        if properties:
            data += bytearray([TAG.PROPERTY, properties])

        if d.counter > 0:
            data += Tlv(TAG.IMF, struct.pack('>I', d.counter))

        self.send_apdu(INS.PUT, 0, 0, bytes(data))
        return Credential(key, d.oath_type, d.touch)

    def list(self):
        def _gen_creds():
            resp = self.send_apdu(INS.LIST, 0, 0)
            while resp:
                length = six.indexbytes(resp, 1) - 1
                oath_type = OATH_TYPE(MASK.TYPE & six.indexbytes(resp, 2))
                key = resp[3:3 + length]
                yield Credential(key, oath_type)
                resp = resp[3 + length:]

        return list(_gen_creds())

    def calculate(self, cred, timestamp=None):

        # The 4.2.0-4.2.6 firmwares have a known issue with credentials that
        # require touch: If this action is performed within 2 seconds of a
        # command resulting in a long response (over 54 bytes),
        # the command will hang. A workaround is to send an invalid command
        # (resulting in a short reply) prior to the "calculate" command.
        if self._426device and cred.touch:
            self._driver.send_apdu(0, 0, 0, 0, '', check=SW.INVALID_INSTRUCTION)

        if timestamp is None:
            timestamp = int(time.time())
        if cred.oath_type == OATH_TYPE.TOTP:
            valid_from = timestamp - (timestamp % cred.period)
            valid_to = valid_from + cred.period
            challenge = time_challenge(timestamp, period=cred.period)
        else:
            valid_from = timestamp
            valid_to = float('Inf')
            challenge = b''
        data = Tlv(TAG.NAME, cred.key) + Tlv(TAG.CHALLENGE, challenge)
        resp = self.send_apdu(INS.CALCULATE, 0, 0, data)
        resp = parse_tlvs(resp)[0].value
        # Manual dynamic truncation is required
        # for Steam entries, so let's do it for all.
        digits = six.indexbytes(resp, 0)
        resp = resp[1:]
        offset = six.indexbytes(resp, -1) & 0xF
        code_data = resp[offset:offset + 4]
        code_data = parse_truncated(code_data)
        code_value = format_code(code_data, digits, steam=cred.is_steam)
        return Code(code_value, valid_from, valid_to)

    def delete(self, cred):
        data = Tlv(TAG.NAME, cred.key)
        self.send_apdu(INS.DELETE, 0, 0, data)

    def calculate_all(self, timestamp=None):
        if timestamp is None:
            timestamp = int(time.time())

        def _gen_all():
            valid_from = timestamp - (timestamp % 30)
            valid_to = valid_from + 30
            data = Tlv(TAG.CHALLENGE, time_challenge(timestamp))
            resp = self.send_apdu(INS.CALCULATE_ALL, 0, 0x01, data)
            tlvs = parse_tlvs(resp)
            while tlvs:
                key = tlvs.pop(0).value
                resp = tlvs.pop(0)
                oath_type = OATH_TYPE.HOTP if resp.tag == TAG.NO_RESPONSE else \
                    OATH_TYPE.TOTP
                touch = resp.tag == TAG.TOUCH
                cred = Credential(key, oath_type, touch)

                if resp.tag == TAG.TRUNCATED_RESPONSE:
                    if cred.period != 30 or cred.is_steam:
                        code = self.calculate(cred, timestamp)
                    else:
                        digits = six.indexbytes(resp.value, 0)
                        code_value = parse_truncated(resp.value[1:])
                        code_value = format_code(code_value, digits)
                        code = Code(code_value, valid_from, valid_to)
                else:
                    code = None

                yield cred, code
        return list(_gen_all())

    def set_password(self, password):
        key = self.derive_key(password)
        keydata = bytearray([OATH_TYPE.TOTP | ALGO.SHA1]) + key
        challenge = os.urandom(8)
        h = hmac.HMAC(key, hashes.SHA1(), default_backend())
        h.update(challenge)
        response = h.finalize()
        data = Tlv(TAG.KEY, keydata) + Tlv(TAG.CHALLENGE, challenge) + Tlv(
            TAG.RESPONSE, response)
        self.send_apdu(INS.SET_CODE, 0, 0, data)
        return key

    def clear_password(self):
        self.send_apdu(INS.SET_CODE, 0, 0, Tlv(TAG.KEY, b''))

    def validate(self, key):
        h = hmac.HMAC(key, hashes.SHA1(), default_backend())
        h.update(self._challenge)
        response = h.finalize()
        challenge = os.urandom(8)
        h = hmac.HMAC(key, hashes.SHA1(), default_backend())
        h.update(challenge)
        verification = h.finalize()
        data = Tlv(TAG.RESPONSE, response) + Tlv(TAG.CHALLENGE, challenge)
        resp = self.send_apdu(INS.VALIDATE, 0, 0, data)
        if parse_tlvs(resp)[0].value != verification:
            raise ValueError(
                'Response from validation does not match verification!')
        self._challenge = None
