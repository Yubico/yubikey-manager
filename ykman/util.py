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

__all__ = ['CAPABILITY', 'Mode']


class CAPABILITY(object):
    OTP = 0x01
    U2F = 0x02
    CCID = 0x04
    OPGP = 0x08
    PIV = 0x10
    OATH = 0x20


class Mode(object):
    _modes = [  # OTP, U2F, CCID
        (True, False, False),  # 0x00 - OTP
        (False, False, True),  # 0x01 - CCID
        (True, False, True),  # 0x02 - OTP+CCID
        (False, True, False),  # 0x03 - U2F
        (True, True, False),  # 0x04 - OTP+U2F
        (False, True, True),  # 0x05 - U2F+CCID
        (True, True, True)  # 0x06 - OTP+U2F+CCID
    ]

    def __init__(self, otp=False, u2f=False, ccid=False):
        self.otp = bool(otp)
        self.u2f = bool(u2f)
        self.ccid = bool(ccid)
        try:
            self.code = self._modes.index((self.otp, self.u2f, self.ccid))
        except ValueError:
            raise ValueError('Invalid mode!')

    def __str__(self):
        return '+'.join(filter(None, [
            self.otp and 'OTP',
            self.u2f and 'U2F',
            self.ccid and 'CCID'
        ]))

    @classmethod
    def from_code(cls, code):
        code = code & 0b00000111
        return cls(*cls._modes[code])
