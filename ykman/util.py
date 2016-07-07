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

from enum import IntEnum
from binascii import b2a_hex, a2b_hex
from .yubicommon.compat import byte2int, text_type
from .native.pyusb import get_usb_backend
import usb.core


__all__ = ['CAPABILITY', 'TRANSPORT', 'Mode', 'parse_tlv_list',
           'read_version_usb', 'list_yubikeys']


class BitflagEnum(IntEnum):
    @classmethod
    def split(cls, flags):
        return (c for c in cls if c & flags)

    @staticmethod
    def has(flags, check):
        return flags & check == check


class CAPABILITY(BitflagEnum):
    OTP = 0x01
    U2F = 0x02
    CCID = 0x04
    OPGP = 0x08
    PIV = 0x10
    OATH = 0x20
    NFC = 0x40


class TRANSPORT(BitflagEnum):
    OTP = CAPABILITY.OTP
    U2F = CAPABILITY.U2F
    CCID = CAPABILITY.CCID
    NFC = CAPABILITY.NFC

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


def parse_tlv_list(data):
    parsed = {}
    while data:
        t, l, data = byte2int(data[0]), byte2int(data[1]), data[2:]
        parsed[t], data = data[:l], data[l:]
    return parsed


_HEX = b'0123456789abcdef'
_MODHEX = b'cbdefghijklnrtuv'
_MODHEX_TO_HEX = dict((_MODHEX[i], _HEX[i:i+1]) for i in range(16))
_HEX_TO_MODHEX = dict((_HEX[i], _MODHEX[i:i+1]) for i in range(16))


def modhex_decode(value):
    if isinstance(value, text_type):
        value = value.encode('ascii')
    return a2b_hex(b''.join(_MODHEX_TO_HEX[c] for c in value))


def modhex_encode(value):
    return b''.join(_HEX_TO_MODHEX[c] for c in b2a_hex(value)).decode('ascii')


_YUBIKEY_PIDS = {
    # YubiKey Standard
    0x0010: TRANSPORT.OTP,

    # YubiKey NEO
    0x0110: TRANSPORT.OTP,
    0x0111: TRANSPORT.OTP | TRANSPORT.CCID,
    0x0112: TRANSPORT.CCID,
    0x0113: TRANSPORT.U2F,
    0x0114: TRANSPORT.OTP | TRANSPORT.U2F,
    0x0115: TRANSPORT.U2F | TRANSPORT.CCID,
    0x0116: TRANSPORT.OTP | TRANSPORT.CCID | TRANSPORT.U2F,

    # Security Key by Yubico
    0x0120: TRANSPORT.U2F,

    # YubiKey 4
    0x0401: TRANSPORT.OTP,
    0x0402: TRANSPORT.U2F,
    0x0403: TRANSPORT.OTP | TRANSPORT.U2F,
    0x0404: TRANSPORT.CCID,
    0x0405: TRANSPORT.OTP | TRANSPORT.U2F,
    0x0406: TRANSPORT.U2F | TRANSPORT.CCID,
    0x0407: TRANSPORT.OTP | TRANSPORT.CCID | TRANSPORT.U2F,

    # YubiKey Plus
    0x0410: TRANSPORT.OTP | TRANSPORT.U2F,
}


def _yubikeys():
    found = []  # Composite devices are listed multiple times on Windows...
    for dev in usb.core.find(True, idVendor=0x1050, backend=get_usb_backend()):
        if dev.idProduct in _YUBIKEY_PIDS:
            addr = (dev.bus, dev.address)
            if addr not in found:
                found.append(addr)
                yield dev


def list_yubikeys():
    return [_YUBIKEY_PIDS[dev.idProduct] for dev in _yubikeys()]


def read_version_usb():
    v_int = next(_yubikeys()).bcdDevice
    return ((v_int >> 8) % 16, (v_int >> 4) % 16, v_int % 16)
