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

"""Scancode map for US English keyboard layout"""

SHIFT = 0x80

scancodes = {
    "a": 0x04,
    "b": 0x05,
    "c": 0x06,
    "d": 0x07,
    "e": 0x08,
    "f": 0x09,
    "g": 0x0A,
    "h": 0x0B,
    "i": 0x0C,
    "j": 0x0D,
    "k": 0x0E,
    "l": 0x0F,
    "m": 0x10,
    "n": 0x11,
    "o": 0x12,
    "p": 0x13,
    "q": 0x14,
    "r": 0x15,
    "s": 0x16,
    "t": 0x17,
    "u": 0x18,
    "v": 0x19,
    "w": 0x1A,
    "x": 0x1B,
    "y": 0x1C,
    "z": 0x1D,
    "A": 0x04 | SHIFT,
    "B": 0x05 | SHIFT,
    "C": 0x06 | SHIFT,
    "D": 0x07 | SHIFT,
    "E": 0x08 | SHIFT,
    "F": 0x09 | SHIFT,
    "G": 0x0A | SHIFT,
    "H": 0x0B | SHIFT,
    "I": 0x0C | SHIFT,
    "J": 0x0D | SHIFT,
    "K": 0x0E | SHIFT,
    "L": 0x0F | SHIFT,
    "M": 0x10 | SHIFT,
    "N": 0x11 | SHIFT,
    "O": 0x12 | SHIFT,
    "P": 0x13 | SHIFT,
    "Q": 0x14 | SHIFT,
    "R": 0x15 | SHIFT,
    "S": 0x16 | SHIFT,
    "T": 0x17 | SHIFT,
    "U": 0x18 | SHIFT,
    "V": 0x19 | SHIFT,
    "W": 0x1A | SHIFT,
    "X": 0x1B | SHIFT,
    "Y": 0x1C | SHIFT,
    "Z": 0x1D | SHIFT,
    "0": 0x27,
    "1": 0x1E,
    "2": 0x1F,
    "3": 0x20,
    "4": 0x21,
    "5": 0x22,
    "6": 0x23,
    "7": 0x24,
    "8": 0x25,
    "9": 0x26,
    "\t": 0x2B,
    "\n": 0x28,
    "!": 0x1E | SHIFT,
    '"': 0x34 | SHIFT,
    "#": 0x20 | SHIFT,
    "$": 0x21 | SHIFT,
    "%": 0x22 | SHIFT,
    "&": 0x24 | SHIFT,
    "'": 0x34,
    "`": 0x35,
    "(": 0x26 | SHIFT,
    ")": 0x27 | SHIFT,
    "*": 0x25 | SHIFT,
    "+": 0x2E | SHIFT,
    ",": 0x36,
    "-": 0x2D,
    ".": 0x37,
    "/": 0x38,
    ":": 0x33 | SHIFT,
    ";": 0x33,
    "<": 0x36 | SHIFT,
    "=": 0x2E,
    ">": 0x37 | SHIFT,
    "?": 0x38 | SHIFT,
    "@": 0x1F | SHIFT,
    "[": 0x2F,
    "\\": 0x32,
    "]": 0x30,
    "^": 0xA3,
    "_": 0xAD,
    "{": 0x2F | SHIFT,
    "}": 0x30 | SHIFT,
    "|": 0x32 | SHIFT,
    "~": 0x35 | SHIFT,
    " ": 0x2C,
}
