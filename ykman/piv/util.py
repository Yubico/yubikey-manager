# Copyright (c) 2018 Yubico AB
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

from enum import IntEnum, unique


@unique
class SW(IntEnum):
    NO_SPACE = 0x6a84
    COMMAND_ABORTED = 0x6f00
    MORE_DATA = 0x61
    INVALID_INSTRUCTION = 0x6d00
    NOT_FOUND = 0x6a82
    ACCESS_DENIED = 0x6982
    AUTHENTICATION_BLOCKED = 0x6983
    INCORRECT_PARAMETERS = 0x6a80

    @staticmethod
    def is_verify_fail(sw, applet_version):
        if applet_version < (1, 0, 4):
            return 0x6300 <= sw <= 0x63ff
        else:
            return 0x63c0 <= sw <= 0x63cf

    @classmethod
    def tries_left(cls, sw, applet_version):
        # Blocked, 0 tries left.
        if sw == SW.AUTHENTICATION_BLOCKED:
            return 0

        if not cls.is_verify_fail(sw, applet_version):
            raise ValueError(
                'Cannot read remaining tries from status word: %x' % sw)

        if applet_version < (1, 0, 4):
            return sw & 0xff
        else:
            return sw & 0xf
