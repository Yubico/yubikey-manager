#  vim: set fileencoding=utf-8 :

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

from __future__ import unicode_literals


"""Scancode map for DE German keyboard layout"""

SHIFT = 0x80

scancodes = {
    'a': 0x04,
    'b': 0x05,
    'c': 0x06,
    'd': 0x07,
    'e': 0x08,
    'f': 0x09,
    'g': 0x0a,
    'h': 0x0b,
    'i': 0x0c,
    'j': 0x0d,
    'k': 0x0e,
    'l': 0x0f,
    'm': 0x10,
    'n': 0x11,
    'o': 0x12,
    'p': 0x13,
    'q': 0x14,
    'r': 0x15,
    's': 0x16,
    't': 0x17,
    'u': 0x18,
    'v': 0x19,
    'w': 0x1a,
    'x': 0x1b,
    'y': 0x1d,
    'z': 0x1c,
    'A': 0x04 | SHIFT,
    'B': 0x05 | SHIFT,
    'C': 0x06 | SHIFT,
    'D': 0x07 | SHIFT,
    'E': 0x08 | SHIFT,
    'F': 0x09 | SHIFT,
    'G': 0x0a | SHIFT,
    'H': 0x0b | SHIFT,
    'I': 0x0c | SHIFT,
    'J': 0x0d | SHIFT,
    'K': 0x0e | SHIFT,
    'L': 0x0f | SHIFT,
    'M': 0x10 | SHIFT,
    'N': 0x11 | SHIFT,
    'O': 0x12 | SHIFT,
    'P': 0x13 | SHIFT,
    'Q': 0x14 | SHIFT,
    'R': 0x15 | SHIFT,
    'S': 0x16 | SHIFT,
    'T': 0x17 | SHIFT,
    'U': 0x18 | SHIFT,
    'V': 0x19 | SHIFT,
    'W': 0x1a | SHIFT,
    'X': 0x1b | SHIFT,
    'Y': 0x1d | SHIFT,
    'Z': 0x1c | SHIFT,
    '0': 0x27,
    '1': 0x1e,
    '2': 0x1f,
    '3': 0x20,
    '4': 0x21,
    '5': 0x22,
    '6': 0x23,
    '7': 0x24,
    '8': 0x25,
    '9': 0x26,
    '\t': 0x2b,
    '\n': 0x28,
    '!': 0x1e | SHIFT,
    '"': 0x1f | SHIFT,
    '#': 0x32,
    '$': 0x21 | SHIFT,
    '%': 0x22 | SHIFT,
    '&': 0x23 | SHIFT,
    "'": 0x32 | SHIFT,
    '(': 0x25 | SHIFT,
    ')': 0x26 | SHIFT,
    '*': 0x30 | SHIFT,
    '+': 0x30,
    ',': 0x36,
    '-': 0x38,
    '.': 0x37,
    '/': 0x24 | SHIFT,
    ':': 0x37 | SHIFT,
    ';': 0x36 | SHIFT,
    '<': 0x64,
    '=': 0x27 | SHIFT,
    '>': 0x64 | SHIFT,
    '?': 0x2d | SHIFT,
    '^': 0x35,
    '_': 0x38 | SHIFT,
    ' ': 0x2c,
    '`': 0x2d | SHIFT,
    '§': 0x20 | SHIFT,
    '´': 0x2e,
    'Ä': 0x34 | SHIFT,
    'Ö': 0x33 | SHIFT,
    'Ü': 0x2f | SHIFT,
    'ß': 0x2d,
    'ä': 0x34,
    'ö': 0x33,
    'ü': 0x2f
}
