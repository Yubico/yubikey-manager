# Copyright (c) 2020 Yubico AB
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

from __future__ import absolute_import, unicode_literals

from enum import Enum, IntEnum, unique, auto
from binascii import b2a_hex
import six
import abc


class BitflagEnum(IntEnum):
    @classmethod
    def split(cls, flags):
        return [c for c in cls if c & flags]

    @staticmethod
    def has(flags, check):
        return flags & check == check


class INTERFACE(Enum):
    USB = auto()
    NFC = auto()


@unique
class TRANSPORT(BitflagEnum):
    OTP = 0x01
    FIDO = 0x02
    CCID = 0x04

    @staticmethod
    def usb_transports():
        return TRANSPORT.OTP | TRANSPORT.CCID | TRANSPORT.FIDO


@unique
class AID(bytes, Enum):
    OTP = b"\xa0\x00\x00\x05\x27\x20\x01"
    MGMT = b"\xa0\x00\x00\x05\x27\x47\x11\x17"
    OPGP = b"\xd2\x76\x00\x01\x24\x01"
    OATH = b"\xa0\x00\x00\x05\x27\x21\x01"
    PIV = b"\xa0\x00\x00\x03\x08"
    FIDO = b"\xa0\x00\x00\x06\x47\x2f\x00\x01"


@unique
class APPLICATION(BitflagEnum):
    OTP = 0x01
    U2F = 0x02
    OPGP = 0x08
    PIV = 0x10
    OATH = 0x20
    FIDO2 = 0x200

    def __str__(self):
        if self == APPLICATION.U2F:
            return "FIDO U2F"
        elif self == APPLICATION.FIDO2:
            return "FIDO2"
        elif self == APPLICATION.OPGP:
            return "OpenPGP"
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
            return "Keychain (USB-A)"
        elif self == FORM_FACTOR.USB_A_NANO:
            return "Nano (USB-A)"
        elif self == FORM_FACTOR.USB_C_KEYCHAIN:
            return "Keychain (USB-C)"
        elif self == FORM_FACTOR.USB_C_NANO:
            return "Nano (USB-C)"
        elif self == FORM_FACTOR.USB_C_LIGHTNING:
            return "Keychain (USB-C, Lightning)"
        elif self == FORM_FACTOR.UNKNOWN:
            return "Unknown"

    @classmethod
    def from_code(cls, code):
        if code and not isinstance(code, int):
            raise ValueError("Invalid form factor code: {}".format(code))
        return cls(code) if code in cls.__members__.values() else cls.UNKNOWN


@unique
class YUBIKEY(Enum):
    YKS = "YubiKey Standard"
    NEO = "YubiKey NEO"
    SKY = "Security Key by Yubico"
    YKP = "YubiKey Plus"
    YK4 = "YubiKey 4"

    def get_pid(self, transports):
        suffix = "_".join(t.name for t in TRANSPORT.split(transports))
        return PID[self.name + "_" + suffix]


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
        return YUBIKEY[self.name.split("_", 1)[0]]

    def get_transports(self):
        return sum(TRANSPORT[x] for x in self.name.split("_")[1:])


class YubiKeyDevice(abc.ABC):
    """YubiKey device reference"""

    def __init__(self, fingerprint):
        self._fingerprint = fingerprint

    @property
    def fingerprint(self):
        """Used to identify that device references from different enumerations represent
        the same physical YubiKey. This fingerprint is not stable between sessions, or
        after un-plugging, and re-plugging a device."""
        return self._fingerprint

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.fingerprint == other.fingerprint

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.fingerprint)

    def __repr__(self):
        return "%s(fingerprint=%r)" % (type(self).__name__, self.fingerprint,)


class CommandError(Exception):
    """An error response from a YubiKey"""


class BadResponseError(CommandError):
    """Invalid response data from the YubiKey"""


class TimeoutError(CommandError):
    """An operation timed out waiting for something"""


class ApplicationNotAvailableError(CommandError):
    """The application is either disabled or not supported on this YubiKey"""


class NotSupportedError(ValueError):
    """Attempting an action that is not supported on this YubiKey"""


def int2bytes(value, min_len=0):
    buf = []
    while value > 0xFF:
        buf.append(value & 0xFF)
        value >>= 8
    buf.append(value)
    return bytes(bytearray(reversed(buf))).rjust(min_len, b"\0")


def bytes2int(data):
    return int(b2a_hex(data), 16)


def _tlv_parse_tag(data, offs=0):
    t = six.indexbytes(data, offs)
    if t & 0x1F != 0x1F:
        return t, 1
    else:
        t = t << 8 | six.indexbytes(data, offs + 1)
        return t, 2


def _tlv_parse_length(data, offs=0):
    ln = six.indexbytes(data, offs)
    offs += 1
    if ln > 0x80:
        n_bytes = ln - 0x80
        ln = bytes2int(data[offs : offs + n_bytes])
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
            return b""
        return bytes(self[-ln:])

    def __repr__(self):
        return "{}(tag={:02x}, value={})".format(
            self.__class__.__name__, self.tag, b2a_hex(self.value).decode("ascii")
        )

    def __new__(cls, *args):
        if len(args) == 1:
            data = args[0]
            if isinstance(data, int):  # Called with tag only, blank value
                tag = data
                value = b""
            else:  # Called with binary TLV data
                tag, tag_ln = _tlv_parse_tag(data)
                ln, ln_ln = _tlv_parse_length(data, tag_ln)
                offs = tag_ln + ln_ln
                value = data[offs : offs + ln]
        elif len(args) == 2:  # Called with tag and value.
            (tag, value) = args
        else:
            raise TypeError(
                "{}() takes at most 2 arguments ({} given)".format(cls, len(args))
            )

        data = bytearray([])
        if tag <= 0xFF:
            data.append(tag)
        else:
            tag_1 = tag >> 8
            if tag_1 > 0xFF or tag_1 & 0x1F != 0x1F:
                raise ValueError("Unsupported tag value")
            tag_2 = tag & 0xFF
            data.extend([tag_1, tag_2])
        length = len(value)
        if length < 0x80:
            data.append(length)
        elif length < 0xFF:
            data.extend([0x81, length])
        else:
            data.extend([0x82, length >> 8, length & 0xFF])
        data += value

        return super(Tlv, cls).__new__(cls, bytes(data))

    @classmethod
    def parse_from(cls, data):
        tlv = cls(data)
        return tlv, data[len(tlv) :]

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
    def unwrap(cls, tag, data):
        tlv = cls(data)
        if tlv.tag != tag:
            raise ValueError("Wrong tag, got %02x expected %02x" % (tlv.tag, tag))
        return tlv.value
