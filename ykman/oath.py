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

from yubikit.oath import OATH_TYPE
from time import time
import struct


STEAM_CHAR_TABLE = "23456789BCDFGHJKMNPQRTVWXY"


def is_hidden(credential):
    return credential.issuer == "_hidden"


def is_steam(credential):
    return credential.oath_type == OATH_TYPE.TOTP and credential.issuer == "Steam"


def calculate_steam(app, credential, timestamp=None):
    timestamp = int(timestamp or time())
    resp = app.calculate(credential.id, struct.pack(">q", timestamp // 30))
    offset = resp[-1] & 0x0F
    code = struct.unpack(">I", resp[offset : offset + 4])[0] & 0x7FFFFFFF
    chars = []
    for i in range(5):
        chars.append(STEAM_CHAR_TABLE[code % len(STEAM_CHAR_TABLE)])
        code //= len(STEAM_CHAR_TABLE)
    return "".join(chars)


def is_in_fips_mode(app):
    return app.locked
