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
import re
import logging
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from enum import Enum, IntEnum, unique
from base64 import b32decode
from binascii import b2a_hex, a2b_hex
from OpenSSL import crypto
from .scancodes import KEYBOARD_LAYOUT


logger = logging.getLogger(__name__)


PEM_IDENTIFIER = b'-----BEGIN'


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
    U2F = b'\xa0\x00\x00\x06\x47\x2f\x00\x01'  # Official
    U2F_YUBICO = b'\xa0\x00\x00\x05\x27\x10\x02'  # Yubico - No longer used


@unique
class TRANSPORT(BitflagEnum):
    OTP = 0x01
    FIDO = 0x02
    CCID = 0x04

    @staticmethod
    def usb_transports():
        return TRANSPORT.OTP | TRANSPORT.CCID | TRANSPORT.FIDO


@unique
class APPLICATION(BitflagEnum):
    OTP = 0x01
    U2F = 0x02
    OPGP = 0x08
    PIV = 0x10
    OATH = 0x20
    FIDO2 = 0x200

    @staticmethod
    def dependent_on_ccid():
        return APPLICATION.OPGP | APPLICATION.OATH | APPLICATION.PIV

    def __str__(self):
        if self == APPLICATION.U2F:
            return 'FIDO U2F'
        elif self == APPLICATION.FIDO2:
            return 'FIDO2'
        elif self == APPLICATION.OPGP:
            return 'OpenPGP'
        else:
            return self.name


@unique
class FORM_FACTOR(IntEnum):
    UNKNOWN = 0x00
    USB_A_KEYCHAIN = 0x01
    USB_A_NANO = 0x02
    USB_C_KEYCHAIN = 0x03
    USB_C_NANO = 0x04
    USB_C_LIGHTNING = 0x05

    def __str__(self):
        if self == FORM_FACTOR.USB_A_KEYCHAIN:
            return 'Keychain (USB-A)'
        elif self == FORM_FACTOR.USB_A_NANO:
            return 'Nano (USB-A)'
        elif self == FORM_FACTOR.USB_C_KEYCHAIN:
            return 'Keychain (USB-C)'
        elif self == FORM_FACTOR.USB_C_NANO:
            return 'Nano (USB-C)'
        elif self == FORM_FACTOR.USB_C_LIGHTNING:
            return 'Keychain (USB-C, Lightning)'
        elif self == FORM_FACTOR.UNKNOWN:
            return 'Unknown.'

    @classmethod
    def from_code(cls, code):
        if code and not isinstance(code, int):
            raise ValueError('Invalid form factor code: {}'.format(code))
        return cls(code) if code in cls.__members__.values() else cls.UNKNOWN


class Cve201715361VulnerableError(Exception):
    """Thrown if on-chip RSA key generation is attempted on a YubiKey vulnerable
    to CVE-2017-15361."""

    def __init__(self, f_version):
        self.f_version = f_version

    def __str__(self):
        return (
            'On-chip RSA key generation on this YubiKey has been blocked.\n'
            'Please see https://yubi.co/ysa201701 for details.'
        )


@unique
class YUBIKEY(Enum):
    YKS = 'YubiKey Standard'
    NEO = 'YubiKey NEO'
    SKY = 'Security Key by Yubico'
    YKP = 'YubiKey Plus'
    YK4 = 'YubiKey 4'

    def get_pid(self, transports):
        suffix = '_'.join(t.name for t in TRANSPORT.split(transports))
        return PID[self.name + '_' + suffix]


@unique
class PID(IntEnum):
    YKS_OTP = 0x0010
    NEO_OTP = 0x0110
    NEO_OTP_CCID = 0x0111
    NEO_CCID = 0x0112
    NEO_FIDO = 0x0113
    NEO_OTP_FIDO = 0x0114
    NEO_FIDO_CCID = 0x0115
    NEO_OTP_FIDO_CCID = 0x0116
    SKY_FIDO = 0x0120
    YK4_OTP = 0x0401
    YK4_FIDO = 0x0402
    YK4_OTP_FIDO = 0x0403
    YK4_CCID = 0x0404
    YK4_OTP_CCID = 0x0405
    YK4_FIDO_CCID = 0x0406
    YK4_OTP_FIDO_CCID = 0x0407
    YKP_OTP_FIDO = 0x0410

    def get_type(self):
        return YUBIKEY[self.name.split('_', 1)[0]]

    def get_transports(self):
        return sum(TRANSPORT[x] for x in self.name.split('_')[1:])


class Mode(object):
    _modes = [
        TRANSPORT.OTP,  # 0x00
        TRANSPORT.CCID,  # 0x01
        TRANSPORT.OTP | TRANSPORT.CCID,  # 0x02
        TRANSPORT.FIDO,  # 0x03
        TRANSPORT.OTP | TRANSPORT.FIDO,  # 0x04
        TRANSPORT.FIDO | TRANSPORT.CCID,  # 0x05
        TRANSPORT.OTP | TRANSPORT.FIDO | TRANSPORT.CCID  # 0x06
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

    @classmethod
    def from_pid(cls, pid):
        return cls(PID(pid).get_transports())

    __hash__ = None


def _tlv_parse_tag(data, offs=0):
    t = six.indexbytes(data, offs)
    if t & 0x1f != 0x1f:
        return t, 1
    else:
        t = t << 8 | six.indexbytes(data, offs+1)
        return t, 2


def _tlv_parse_length(data, offs=0):
    ln = six.indexbytes(data, offs)
    offs += 1
    if ln > 0x80:
        n_bytes = ln - 0x80
        ln = bytes2int(data[offs:offs + n_bytes])
    else:
        n_bytes = 0
    return ln, n_bytes + 1


class Tlv(bytes):

    @property
    def tag(self):
        return _tlv_parse_tag(self)[0]

    @property
    def length(self):
        _, offs = _tlv_parse_tag(self)
        return _tlv_parse_length(self, offs)[0]

    @property
    def value(self):
        ln = self.length
        if ln == 0:
            return b''
        return bytes(self[-ln:])

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
                tag, tag_ln = _tlv_parse_tag(data)
                ln, ln_ln = _tlv_parse_length(data, tag_ln)
                offs = tag_ln + ln_ln
                value = data[offs:offs+ln]
        elif len(args) == 2:  # Called with tag and value.
            (tag, value) = args
        else:
            raise TypeError('{}() takes at most 2 arguments ({} given)'.format(
                cls, len(args)))

        data = bytearray([])
        if tag <= 0xff:
            data.append(tag)
        else:
            tag_1 = tag >> 8
            if tag_1 > 0xff or tag_1 & 0x1f != 0x1f:
                raise ValueError('Unsupported tag value')
            tag_2 = tag & 0xff
            data.extend([tag_1, tag_2])
        length = len(value)
        if length < 0x80:
            data.append(length)
        elif length < 0xff:
            data.extend([0x81, length])
        else:
            data.extend([0x82, length >> 8, length & 0xff])
        data += value

        return super(Tlv, cls).__new__(cls, bytes(data))

    @classmethod
    def parse_from(cls, data):
        tlv = cls(data)
        return tlv, data[len(tlv):]

    @classmethod
    def parse_list(cls, data):
        res = []
        while data:
            tlv, data = cls.parse_from(data)
            res.append(tlv)
        return res

    @classmethod
    def parse_dict(cls, data):
        return dict((tlv.tag, tlv.value) for tlv in cls.parse_list(data))

    @classmethod
    def unpack(cls, tag, data):
        tlv = cls(data)
        if tlv.tag != tag:
            raise ValueError('Wrong tag, got {:02x} expected {:02x}'.format(
                tlv.tag,
                tag
            ))
        return tlv.value


parse_tlvs = Tlv.parse_list  # Deprecated, use Tlv.parse_list directly


class MissingLibrary(object):
    def __init__(self, message):
        self._message = message

    def __getattr__(self, name):
        raise AttributeError(self._message)


def int2bytes(value):
    buf = []
    while value > 0xff:
        buf.append(value & 0xff)
        value >>= 8
    buf.append(value)
    return bytes(bytearray(reversed(buf)))


def bytes2int(data):
    return int(b2a_hex(data), 16)


_HEX = b'0123456789abcdef'
_MODHEX = b'cbdefghijklnrtuv'
_MODHEX_TO_HEX = dict((_MODHEX[i], _HEX[i:i+1]) for i in range(16))
_HEX_TO_MODHEX = dict((_HEX[i], _MODHEX[i:i+1]) for i in range(16))
DEFAULT_PW_CHAR_BLACKLIST = ['\t', '\n', ' ']


def ensure_not_cve201715361_vulnerable_firmware_version(f_version):
    if is_cve201715361_vulnerable_firmware_version(f_version):
        raise Cve201715361VulnerableError(f_version)


def is_cve201715361_vulnerable_firmware_version(f_version):
    return (4, 2, 0) <= f_version < (4, 3, 5)


def modhex_decode(value):
    if isinstance(value, six.text_type):
        value = value.encode('ascii')
    return a2b_hex(b''.join(_MODHEX_TO_HEX[c] for c in value))


def modhex_encode(value):
    return b''.join(_HEX_TO_MODHEX[c] for c in b2a_hex(value)).decode('ascii')


def generate_static_pw(
        length,
        keyboard_layout=KEYBOARD_LAYOUT.MODHEX,
        blacklist=DEFAULT_PW_CHAR_BLACKLIST):
    chars = [k for k in keyboard_layout.value.keys() if k not in blacklist]
    sr = random.SystemRandom()
    return ''.join([sr.choice(chars) for _ in range(length)])


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
        h = hashes.SHA1()
    elif algo.upper() == 'SHA256':
        h = hashes.SHA256()
    elif algo.upper() == 'SHA512':
        h = hashes.SHA512()
    else:
        raise ValueError('Unsupported algorithm!')

    if len(key) > h.block_size:
        h = hashes.Hash(h, default_backend())
        h.update(key)
        key = h.finalize()
    return key


def time_challenge(timestamp, period=30):
    return struct.pack('>q', int(timestamp // period))


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
    if is_pem(data):
        if b'ENCRYPTED' in data:
            if password is None:
                raise TypeError('No password provided for encrypted key.')
        try:
            return serialization.load_pem_private_key(
                data, password, backend=default_backend())
        except ValueError:
            # Cryptography raises ValueError if decryption fails.
            raise
        except Exception:
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
    except Exception:
        pass

    # All parsing failed
    raise ValueError('Could not parse private key.')


def parse_certificates(data, password):
    """
    Identifies, decrypts and returns list of cryptography x509 certificates.
    """

    # PEM
    if is_pem(data):
        certs = []
        for cert in data.split(PEM_IDENTIFIER):
            try:
                certs.append(
                    x509.load_pem_x509_certificate(
                        PEM_IDENTIFIER + cert, default_backend()))
            except Exception:
                pass
        # Could be valid PEM but not certificates.
        if len(certs) > 0:
            return certs

    # PKCS12
    if is_pkcs12(data):
        try:
            p12 = crypto.load_pkcs12(data, password)
            data = crypto.dump_certificate(
                crypto.FILETYPE_PEM, p12.get_certificate())
            return [x509.load_pem_x509_certificate(data, default_backend())]
        except crypto.Error as e:
            raise ValueError(e)

    # DER
    try:
        return [x509.load_der_x509_certificate(data, default_backend())]
    except Exception:
        pass

    raise ValueError('Could not parse certificate.')


def get_leaf_certificates(certs):
    """
    Extracts the leaf certificates from a list of certificates. Leaf
    certificates are ones whose subject does not appear as issuer among the
    others.
    """
    issuers = [cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
               for cert in certs]
    leafs = [cert for cert in certs
             if (cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                 not in issuers)]
    return leafs


def is_pem(data):
    return PEM_IDENTIFIER in data if data else False


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
