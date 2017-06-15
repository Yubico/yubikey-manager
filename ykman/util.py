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
import six
import struct
import hashlib
import re
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from enum import Enum, IntEnum, unique
from base64 import b32decode
from binascii import b2a_hex, a2b_hex
from OpenSSL import crypto

try:
    from urlparse import urlparse, parse_qs
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote, urlparse, parse_qs


class BitflagEnum(IntEnum):
    @classmethod
    def split(cls, flags):
        return (c for c in cls if c & flags)

    @staticmethod
    def has(flags, check):
        return flags & check == check


@unique
class AID(bytes, Enum):
    OTP = b'\xa0\x00\x00\x05\x27\x20\x01'
    MGR = b'\xa0\x00\x00\x05\x27\x47\x11\x17'
    OPGP = b'\xd2\x76\x00\x01\x24\x01'
    OATH = b'\xa0\x00\x00\x05\x27\x21\x01'
    PIV = b'\xa0\x00\x00\x03\x08'


@unique
class CAPABILITY(BitflagEnum):
    OTP = 0x01
    U2F = 0x02
    CCID = 0x04
    OPGP = 0x08
    PIV = 0x10
    OATH = 0x20
    NFC = 0x40

    @staticmethod
    def dependent_on_ccid():
        return CAPABILITY.OPGP | CAPABILITY.OATH | CAPABILITY.PIV


@unique
class TRANSPORT(BitflagEnum):
    OTP = CAPABILITY.OTP
    U2F = CAPABILITY.U2F
    CCID = CAPABILITY.CCID

    @staticmethod
    def usb_transports():
        return TRANSPORT.OTP | TRANSPORT.CCID | TRANSPORT.U2F


class Mode(object):
    _modes = [
        TRANSPORT.OTP,  # 0x00
        TRANSPORT.CCID,  # 0x01
        TRANSPORT.OTP | TRANSPORT.CCID,  # 0x02
        TRANSPORT.U2F,  # 0x03
        TRANSPORT.OTP | TRANSPORT.U2F,  # 0x04
        TRANSPORT.U2F | TRANSPORT.CCID,  # 0x05
        TRANSPORT.OTP | TRANSPORT.U2F | TRANSPORT.CCID  # 0x06
    ]

    def __init__(self, transports):
        try:
            self.code = self._modes.index(transports)
            self._transports = transports
        except ValueError:
            raise ValueError('Invalid mode!')

    @property
    def transports(self):
        return self._transports

    def has_transport(self, transport):
        return TRANSPORT.has(self._transports, transport)

    def __eq__(self, other):
        return other is not None and self.code == other.code

    def __ne__(self, other):
        return other is None or self.code != other.code

    def __str__(self):
        return '+'.join((t.name for t in TRANSPORT.split(self._transports)))

    @classmethod
    def from_code(cls, code):
        code = code & 0b00000111
        return cls(cls._modes[code])


class Tlv(bytes):

    @property
    def tag(self):
        return six.indexbytes(self, 0)

    @property
    def length(self):
        l = six.indexbytes(self, 1)
        offs = 2
        if l > 0x80:
            n_bytes = l - 0x80
            l = b2len(self[offs:offs + n_bytes])
        return l

    @property
    def value(self):
        l = self.length
        if l == 0:
            return b''
        return bytes(self[-l:])

    def __repr__(self):
        return u'{}(tag={:02x}, value={})'.format(
            self.__class__.__name__,
            self.tag,
            b2a_hex(self.value).decode('ascii')
        )

    def __new__(cls, *args):
        if len(args) == 1:
            data = args[0]
            if isinstance(data, int):  # Called with tag only, blank value
                tag = data
                value = b''
            else:  # Called with binary TLV data
                tag = six.indexbytes(data, 0)
                l = six.indexbytes(data, 1)
                offs = 2
                if l > 0x80:
                    n_bytes = l - 0x80
                    l = b2len(data[offs:offs + n_bytes])
                    offs = offs + n_bytes
                value = data[offs:offs+l]
        elif len(args) == 2:  # Called with tag and value.
            (tag, value) = args
        else:
            raise TypeError('{}() takes at most 2 arguments ({} given)'.format(
                cls, len(args)))

        data = bytearray([tag])
        length = len(value)
        if length < 0x80:
            data.append(length)
        elif length < 0xff:
            data.extend([0x81, length])
        else:
            data.extend([0x82, length >> 8, length & 0xff])
        data += value

        return super(Tlv, cls).__new__(cls, bytes(data))


class MissingLibrary(object):
    def __init__(self, message):
        self._message = message

    def __getattr__(self, name):
        raise ValueError(self._message)


def parse_tlvs(data):
    res = []
    while data:
        tlv = Tlv(data)
        data = data[len(tlv):]
        res.append(tlv)
    return res


def b2len(bs):
    l = 0
    for b in six.iterbytes(bs):
        l *= 256
        l += b
    return l


_HEX = b'0123456789abcdef'
_MODHEX = b'cbdefghijklnrtuv'
_MODHEX_TO_HEX = dict((_MODHEX[i], _HEX[i:i+1]) for i in range(16))
_HEX_TO_MODHEX = dict((_HEX[i], _MODHEX[i:i+1]) for i in range(16))
_PW_CHARS = _MODHEX + _MODHEX.upper()


def modhex_decode(value):
    if isinstance(value, six.text_type):
        value = value.encode('ascii')
    return a2b_hex(b''.join(_MODHEX_TO_HEX[c] for c in value))


def modhex_encode(value):
    return b''.join(_HEX_TO_MODHEX[c] for c in b2a_hex(value)).decode('ascii')


def generate_static_pw(length):
    data = os.urandom(length)
    return bytes(bytearray(six.indexbytes(_PW_CHARS, d % len(_PW_CHARS))
                           for d in six.iterbytes(data)))


def derive_key(salt, passphrase):
    kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())
    return kdf.derive(passphrase.encode('utf-8'))


def format_code(code, digits=6, steam=False):
    STEAM_CHAR_TABLE = '23456789BCDFGHJKMNPQRTVWXY'
    if steam:
        chars = []
        for i in range(5):
            chars.append(STEAM_CHAR_TABLE[code % len(STEAM_CHAR_TABLE)])
            code //= len(STEAM_CHAR_TABLE)
        return ''.join(chars)
    else:
        return ('%%0%dd' % digits) % (code % 10 ** digits)


def parse_totp_hash(resp):
    offs = six.indexbytes(resp, -1) & 0xf
    return parse_truncated(resp[offs:offs+4])


def parse_truncated(resp):
    return struct.unpack('>I', resp)[0] & 0x7fffffff


def hmac_shorten_key(key, algo):
    if algo.upper() == 'SHA1':
        h = hashlib.sha1()
    elif algo.upper() == 'SHA256':
        h = hashlib.sha256()
    else:
        raise ValueError('Unsupported algorithm!')
    if len(key) > h.block_size:
        h.update(key)
        key = h.digest()
    return key


def time_challenge(timestamp):
    return struct.pack('>q', int(timestamp // 30))


def parse_uri(val):
    try:
        uri = val.strip()
        parsed = urlparse(uri)
        assert parsed.scheme == 'otpauth'
        params = dict((k, v[0]) for k, v in parse_qs(parsed.query).items())
        params['name'] = unquote(parsed.path)[1:]  # Unquote and strip leading /
        params['type'] = parsed.hostname
        # Issuer can come both in a param and inside name param.
        # We store both in the name field on the key.
        if 'issuer' in params \
                and not params['name'].startswith(params['issuer']):
                    params['name'] = params['issuer'] + ':' + params['name']
        return params
    except:
        raise ValueError('URI seems to have the wrong format.')


def parse_key(val):
    val = val.upper()
    if re.match(r'^([0-9A-F]{2})+$', val):  # hex
        return a2b_hex(val)
    else:
        # Key should be b32 encoded
        return parse_b32_key(val)


def parse_b32_key(key):
    key = key.upper().replace(' ', '')
    key += '=' * (-len(key) % 8)  # Support unpadded
    return b32decode(key)


def parse_private_key(data, password):
    """
    Identifies, decrypts and returns a cryptography private key object.
    """
    # PEM
    if data.startswith(b'-----'):
        if b'ENCRYPTED' in data:
            if password is None:
                raise TypeError('No password provided for encrypted key.')
        try:
            return serialization.load_pem_private_key(
                data, password, backend=default_backend())
        except ValueError:
            # Cryptography raises ValueError if decryption fails.
            raise
        except:
            pass

    # PKCS12
    if is_pkcs12(data):
        try:
            p12 = crypto.load_pkcs12(data, password)
            data = crypto.dump_privatekey(
                crypto.FILETYPE_PEM, p12.get_privatekey())
            return serialization.load_pem_private_key(
                data, password=None, backend=default_backend())
        except crypto.Error as e:
            raise ValueError(e)

    # DER
    try:
        return serialization.load_der_private_key(
            data, password, backend=default_backend())
    except:
        pass

    # All parsing failed
    raise ValueError('Could not parse private key.')


def parse_certificate(data, password):
    """
    Identifies, decrypts and returns a cryptography x509 certficate.
    """
    # PEM
    if data.startswith(b'-----'):
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except:
            pass

    # PKCS12
    if is_pkcs12(data):
        try:
            p12 = crypto.load_pkcs12(data, password)
            data = crypto.dump_certificate(
                crypto.FILETYPE_PEM, p12.get_certificate())
            return x509.load_pem_x509_certificate(data, default_backend())
        except crypto.Error as e:
            raise ValueError(e)

    # DER
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except:
        pass

    raise ValueError('Could not parse certificate.')


def is_pkcs12(data):
    """
    Tries to identify a PKCS12 container.
    The PFX PDU version is assumed to be v3.
    See: https://tools.ietf.org/html/rfc7292.
    """
    if isinstance(data, bytes):
        tlv = Tlv(data)
        if tlv.tag == 0x30:
            header = Tlv(tlv.value)
            return header.tag == 0x02 and header.value == b'\x03'
        return False
    else:
        return False
