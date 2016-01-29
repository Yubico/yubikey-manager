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

__all__ = ['CAPABILITY', 'TRANSPORT', 'Mode', 'parse_tlv_list']


class BitflagEnum(IntEnum):
    @classmethod
    def split(cls, flags):
        return (c for c in cls if c & flags)

    @classmethod
    def has(cls, flags, check):
        return flags & check == check


class CAPABILITY(BitflagEnum):
    OTP = 0x01
    U2F = 0x02
    CCID = 0x04
    OPGP = 0x08
    PIV = 0x10
    OATH = 0x20


class TRANSPORT(BitflagEnum):
    OTP = CAPABILITY.OTP
    U2F = CAPABILITY.U2F
    CCID = CAPABILITY.CCID


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
        return '+'.join((t.name for t in TRANSPORT.split(self._transports))

    @classmethod
    def from_code(cls, code):
        code = code & 0b00000111
        return cls(cls._modes[code])


def parse_tlv_list(data):
    parsed = {}
    while data:
        t, l, data = ord(data[0]), ord(data[1]), data[2:]
        parsed[t], data = data[:l], data[l:]
    return parsed


_HEX = '0123456789abcdef'
_MODHEX = 'cbdefghijklnrtuv'
_MODHEX_TO_HEX = dict(zip(_MODHEX, _HEX))
_HEX_TO_MODHEX = dict(zip(_HEX, _MODHEX))


def modhex_decode(value):
    return ''.join(_MODHEX_TO_HEX[c] for c in value).decode('hex')


def modhex_encode(value):
    return ''.join(_HEX_TO_MODHEX[c] for c in value.encode('hex'))
