# Copyright (c) 2016 Yubico AB
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

from PySide import QtGui
from binascii import a2b_hex
from base64 import b32decode
from ..util import modhex_decode
import re
import struct


class B32Validator(QtGui.QValidator):

    def __init__(self, parent=None):
        super(B32Validator, self).__init__(parent)
        self.partial = re.compile(r'^[ a-z2-7]+$', re.IGNORECASE)

    def fixup(self, value):
        try:
            unpadded = value.upper().rstrip('=').replace(' ', '')
            return b32decode(unpadded + '=' * (-len(unpadded) % 8))
        except:
            return None

    def validate(self, value, pos):
        try:
            if self.fixup(value) is not None:
                return QtGui.QValidator.Acceptable
        except:
            pass
        if self.partial.match(value):
            return QtGui.QValidator.Intermediate
        return QtGui.QValidator.Invalid


class HexValidator(QtGui.QValidator):
    partial_pattern = r'^[ a-f0-9]*$'

    def __init__(self, min_bytes=0, max_bytes=None, parent=None):
        super(HexValidator, self).__init__(parent)
        self.partial = re.compile(self.partial_pattern, re.IGNORECASE)
        self._min = min_bytes
        self._max = max_bytes if max_bytes is not None else float('inf')

    def fixup(self, value):
        try:
            return a2b_hex(value.replace(' ', ''))
        except:
            return None

    def validate(self, value, pos):
        try:
            fixed = self.fixup(value)
            if fixed is not None and self._min <= len(fixed) <= self._max:
                return QtGui.QValidator.Acceptable
        except:
            pass

        if self.partial.match(value) and \
                (len(value.replace(' ', '')) + 1) / 2 <= self._max:
            return QtGui.QValidator.Intermediate

        return QtGui.QValidator.Invalid


class ModhexValidator(HexValidator):
    partial_pattern = r'^[cbdefghijklnrtuv]+$'

    def __init__(self, min_bytes=0, max_bytes=None, parent=None):
        super(ModhexValidator, self).__init__(min_bytes, max_bytes, parent)

    def fixup(self, value):
        try:
            return modhex_decode(value.replace(' ', ''))
        except:
            return None
