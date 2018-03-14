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

"""Scancode map for keyboard layout based on Modhex. Note that this
    layouts allows both upper and lowercase characters."""

SHIFT = 0x80

scancodes = {
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
    'n': 0x11,
    'r': 0x15,
    't': 0x17,
    'u': 0x18,
    'v': 0x19,
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
    'N': 0x11 | SHIFT,
    'R': 0x15 | SHIFT,
    'T': 0x17 | SHIFT,
    'U': 0x18 | SHIFT,
    'V': 0x19 | SHIFT,
}
