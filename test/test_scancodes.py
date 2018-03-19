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

import unittest
from ykman.scancodes import encode, KEYBOARD_LAYOUT


class TestScanMap(unittest.TestCase):

    def test_us_layout(self):
        self.assertEqual(b'\x04', encode('a', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x05', encode('b', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x06', encode('c', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x07', encode('d', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x08', encode('e', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x09', encode('f', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x0a', encode('g', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x0b', encode('h', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x0c', encode('i', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x0d', encode('j', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x0e', encode('k', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x0f', encode('l', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x10', encode('m', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x11', encode('n', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x12', encode('o', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x13', encode('p', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x14', encode('q', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x15', encode('r', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x16', encode('s', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x17', encode('t', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x18', encode('u', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x19', encode('v', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x1a', encode('w', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x1b', encode('x', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x1c', encode('y', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x1d', encode('z', KEYBOARD_LAYOUT.US))

        self.assertEqual(b'\x84', encode('A', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x85', encode('B', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x86', encode('C', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x87', encode('D', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x88', encode('E', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x89', encode('F', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x8a', encode('G', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x8b', encode('H', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x8c', encode('I', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x8d', encode('J', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x8e', encode('K', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x8f', encode('L', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x90', encode('M', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x91', encode('N', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x92', encode('O', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x93', encode('P', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x94', encode('Q', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x95', encode('R', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x96', encode('S', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x97', encode('T', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x98', encode('U', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x99', encode('V', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x9a', encode('W', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x9b', encode('X', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x9c', encode('Y', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x9d', encode('Z', KEYBOARD_LAYOUT.US))

        self.assertEqual(b'\x27', encode('0', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x1e', encode('1', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x1f', encode('2', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x20', encode('3', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x21', encode('4', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x22', encode('5', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x23', encode('6', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x24', encode('7', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x25', encode('8', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x26', encode('9', KEYBOARD_LAYOUT.US))

        self.assertEqual(b'\x2b', encode('\t', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x28', encode('\n', KEYBOARD_LAYOUT.US))

        self.assertEqual(b'\x9e', encode('!', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb4', encode('"', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa0', encode('#', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa1', encode('$', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa2', encode('%', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa4', encode('&', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x34', encode("'", KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa6', encode('(', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa7', encode(')', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa5', encode('*', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xae', encode('+', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x36', encode(',', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x2d', encode('-', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x37', encode('.', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x38', encode('/', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb3', encode(':', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x33', encode(';', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb6', encode('<', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x2e', encode('=', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb7', encode('>', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb8', encode('?', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x9f', encode('@', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x2f', encode('[', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x32', encode('\\', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\x30', encode(']', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xa3', encode('^', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xad', encode('_', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xaf', encode('{', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb0', encode('}', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb2', encode('|', KEYBOARD_LAYOUT.US))
        self.assertEqual(b'\xb5', encode('~', KEYBOARD_LAYOUT.US))

        self.assertEqual(b'\x04\x05\x06', encode('abc', KEYBOARD_LAYOUT.US))
        with self.assertRaises(ValueError):
            encode('ö')

    def test_de_layout(self):
        self.assertEqual(b'\x04', encode('a', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x05', encode('b', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x06', encode('c', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x07', encode('d', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x08', encode('e', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x09', encode('f', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x0a', encode('g', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x0b', encode('h', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x0c', encode('i', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x0d', encode('j', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x0e', encode('k', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x0f', encode('l', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x10', encode('m', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x11', encode('n', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x12', encode('o', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x13', encode('p', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x14', encode('q', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x15', encode('r', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x16', encode('s', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x17', encode('t', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x18', encode('u', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x19', encode('v', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x1a', encode('w', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x1b', encode('x', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x1d', encode('y', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x1c', encode('z', KEYBOARD_LAYOUT.DE))

        self.assertEqual(b'\x84', encode('A', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x85', encode('B', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x86', encode('C', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x87', encode('D', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x88', encode('E', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x89', encode('F', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x8a', encode('G', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x8b', encode('H', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x8c', encode('I', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x8d', encode('J', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x8e', encode('K', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x8f', encode('L', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x90', encode('M', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x91', encode('N', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x92', encode('O', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x93', encode('P', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x94', encode('Q', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x95', encode('R', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x96', encode('S', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x97', encode('T', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x98', encode('U', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x99', encode('V', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x9a', encode('W', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x9b', encode('X', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x9d', encode('Y', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x9c', encode('Z', KEYBOARD_LAYOUT.DE))

        self.assertEqual(b'\x27', encode('0', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x1e', encode('1', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x1f', encode('2', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x20', encode('3', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x21', encode('4', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x22', encode('5', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x23', encode('6', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x24', encode('7', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x25', encode('8', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x26', encode('9', KEYBOARD_LAYOUT.DE))

        self.assertEqual(b'\x2b', encode('\t', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x28', encode('\n', KEYBOARD_LAYOUT.DE))

        self.assertEqual(b'\x32', encode('#', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x30', encode('+', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x36', encode(',', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x38', encode('-', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x64', encode('<', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x35', encode('^', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x2c', encode(' ', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x2e', encode('´', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x2d', encode('ß', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x34', encode('ä', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x33', encode('ö', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x2f', encode('ü', KEYBOARD_LAYOUT.DE))

        self.assertEqual(b'\x9e', encode('!', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\x9f', encode('"', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa1', encode('$', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa2', encode('%', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa3', encode('&', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xb2', encode("'", KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa5', encode('(', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa6', encode(')', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xb0', encode('*', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa4', encode('/', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xb7', encode(':', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xb6', encode(';', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa7', encode('=', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xe4', encode('>', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xad', encode('?', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xb8', encode('_', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xad', encode('`', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xa0', encode('§', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xb4', encode('Ä', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xb3', encode('Ö', KEYBOARD_LAYOUT.DE))
        self.assertEqual(b'\xaf', encode('Ü', KEYBOARD_LAYOUT.DE))

        self.assertEqual(
            b'\xb4\xb3\xaf', encode('ÄÖÜ', KEYBOARD_LAYOUT.DE))
        with self.assertRaises(ValueError):
            encode('@', KEYBOARD_LAYOUT.DE)
