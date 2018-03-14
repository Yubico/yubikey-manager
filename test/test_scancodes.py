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

import unittest
from ykman.scancodes import encode, SCANCODE_MAP


class TestScanMap(unittest.TestCase):

    def test_us_layout(self):
        self.assertEqual(b'\x04', encode('a', SCANCODE_MAP.US))
        self.assertEqual(b'\x05', encode('b', SCANCODE_MAP.US))
        self.assertEqual(b'\x06', encode('c', SCANCODE_MAP.US))
        self.assertEqual(b'\x07', encode('d', SCANCODE_MAP.US))
        self.assertEqual(b'\x08', encode('e', SCANCODE_MAP.US))
        self.assertEqual(b'\x09', encode('f', SCANCODE_MAP.US))
        self.assertEqual(b'\x0a', encode('g', SCANCODE_MAP.US))
        self.assertEqual(b'\x0b', encode('h', SCANCODE_MAP.US))
        self.assertEqual(b'\x0c', encode('i', SCANCODE_MAP.US))
        self.assertEqual(b'\x0d', encode('j', SCANCODE_MAP.US))
        self.assertEqual(b'\x0e', encode('k', SCANCODE_MAP.US))
        self.assertEqual(b'\x0f', encode('l', SCANCODE_MAP.US))
        self.assertEqual(b'\x10', encode('m', SCANCODE_MAP.US))
        self.assertEqual(b'\x11', encode('n', SCANCODE_MAP.US))
        self.assertEqual(b'\x12', encode('o', SCANCODE_MAP.US))
        self.assertEqual(b'\x13', encode('p', SCANCODE_MAP.US))
        self.assertEqual(b'\x14', encode('q', SCANCODE_MAP.US))
        self.assertEqual(b'\x15', encode('r', SCANCODE_MAP.US))
        self.assertEqual(b'\x16', encode('s', SCANCODE_MAP.US))
        self.assertEqual(b'\x17', encode('t', SCANCODE_MAP.US))
        self.assertEqual(b'\x18', encode('u', SCANCODE_MAP.US))
        self.assertEqual(b'\x19', encode('v', SCANCODE_MAP.US))
        self.assertEqual(b'\x1a', encode('w', SCANCODE_MAP.US))
        self.assertEqual(b'\x1b', encode('x', SCANCODE_MAP.US))
        self.assertEqual(b'\x1c', encode('y', SCANCODE_MAP.US))
        self.assertEqual(b'\x1d', encode('z', SCANCODE_MAP.US))

        self.assertEqual(b'\x84', encode('A', SCANCODE_MAP.US))
        self.assertEqual(b'\x85', encode('B', SCANCODE_MAP.US))
        self.assertEqual(b'\x86', encode('C', SCANCODE_MAP.US))
        self.assertEqual(b'\x87', encode('D', SCANCODE_MAP.US))
        self.assertEqual(b'\x88', encode('E', SCANCODE_MAP.US))
        self.assertEqual(b'\x89', encode('F', SCANCODE_MAP.US))
        self.assertEqual(b'\x8a', encode('G', SCANCODE_MAP.US))
        self.assertEqual(b'\x8b', encode('H', SCANCODE_MAP.US))
        self.assertEqual(b'\x8c', encode('I', SCANCODE_MAP.US))
        self.assertEqual(b'\x8d', encode('J', SCANCODE_MAP.US))
        self.assertEqual(b'\x8e', encode('K', SCANCODE_MAP.US))
        self.assertEqual(b'\x8f', encode('L', SCANCODE_MAP.US))
        self.assertEqual(b'\x90', encode('M', SCANCODE_MAP.US))
        self.assertEqual(b'\x91', encode('N', SCANCODE_MAP.US))
        self.assertEqual(b'\x92', encode('O', SCANCODE_MAP.US))
        self.assertEqual(b'\x93', encode('P', SCANCODE_MAP.US))
        self.assertEqual(b'\x94', encode('Q', SCANCODE_MAP.US))
        self.assertEqual(b'\x95', encode('R', SCANCODE_MAP.US))
        self.assertEqual(b'\x96', encode('S', SCANCODE_MAP.US))
        self.assertEqual(b'\x97', encode('T', SCANCODE_MAP.US))
        self.assertEqual(b'\x98', encode('U', SCANCODE_MAP.US))
        self.assertEqual(b'\x99', encode('V', SCANCODE_MAP.US))
        self.assertEqual(b'\x9a', encode('W', SCANCODE_MAP.US))
        self.assertEqual(b'\x9b', encode('X', SCANCODE_MAP.US))
        self.assertEqual(b'\x9c', encode('Y', SCANCODE_MAP.US))
        self.assertEqual(b'\x9d', encode('Z', SCANCODE_MAP.US))

        self.assertEqual(b'\x27', encode('0', SCANCODE_MAP.US))
        self.assertEqual(b'\x1e', encode('1', SCANCODE_MAP.US))
        self.assertEqual(b'\x1f', encode('2', SCANCODE_MAP.US))
        self.assertEqual(b'\x20', encode('3', SCANCODE_MAP.US))
        self.assertEqual(b'\x21', encode('4', SCANCODE_MAP.US))
        self.assertEqual(b'\x22', encode('5', SCANCODE_MAP.US))
        self.assertEqual(b'\x23', encode('6', SCANCODE_MAP.US))
        self.assertEqual(b'\x24', encode('7', SCANCODE_MAP.US))
        self.assertEqual(b'\x25', encode('8', SCANCODE_MAP.US))
        self.assertEqual(b'\x26', encode('9', SCANCODE_MAP.US))

        self.assertEqual(b'\x2b', encode('\t', SCANCODE_MAP.US))
        self.assertEqual(b'\x28', encode('\n', SCANCODE_MAP.US))

        self.assertEqual(b'\x9e', encode('!', SCANCODE_MAP.US))
        self.assertEqual(b'\xb4', encode('"', SCANCODE_MAP.US))
        self.assertEqual(b'\xa0', encode('#', SCANCODE_MAP.US))
        self.assertEqual(b'\xa1', encode('$', SCANCODE_MAP.US))
        self.assertEqual(b'\xa2', encode('%', SCANCODE_MAP.US))
        self.assertEqual(b'\xa4', encode('&', SCANCODE_MAP.US))
        self.assertEqual(b'\x34', encode("'", SCANCODE_MAP.US))
        self.assertEqual(b'\xa6', encode('(', SCANCODE_MAP.US))
        self.assertEqual(b'\xa7', encode(')', SCANCODE_MAP.US))
        self.assertEqual(b'\xa5', encode('*', SCANCODE_MAP.US))
        self.assertEqual(b'\xae', encode('+', SCANCODE_MAP.US))
        self.assertEqual(b'\x36', encode(',', SCANCODE_MAP.US))
        self.assertEqual(b'\x2d', encode('-', SCANCODE_MAP.US))
        self.assertEqual(b'\x37', encode('.', SCANCODE_MAP.US))
        self.assertEqual(b'\x38', encode('/', SCANCODE_MAP.US))
        self.assertEqual(b'\xb3', encode(':', SCANCODE_MAP.US))
        self.assertEqual(b'\x33', encode(';', SCANCODE_MAP.US))
        self.assertEqual(b'\xb6', encode('<', SCANCODE_MAP.US))
        self.assertEqual(b'\x2e', encode('=', SCANCODE_MAP.US))
        self.assertEqual(b'\xb7', encode('>', SCANCODE_MAP.US))
        self.assertEqual(b'\xb8', encode('?', SCANCODE_MAP.US))
        self.assertEqual(b'\x9f', encode('@', SCANCODE_MAP.US))
        self.assertEqual(b'\x2f', encode('[', SCANCODE_MAP.US))
        self.assertEqual(b'\x32', encode('\\', SCANCODE_MAP.US))
        self.assertEqual(b'\x30', encode(']', SCANCODE_MAP.US))
        self.assertEqual(b'\xa3', encode('^', SCANCODE_MAP.US))
        self.assertEqual(b'\xad', encode('_', SCANCODE_MAP.US))
        self.assertEqual(b'\xaf', encode('{', SCANCODE_MAP.US))
        self.assertEqual(b'\xb0', encode('}', SCANCODE_MAP.US))
        self.assertEqual(b'\xb2', encode('|', SCANCODE_MAP.US))
        self.assertEqual(b'\xb5', encode('~', SCANCODE_MAP.US))

        self.assertEqual(b'\x04\x05\x06', encode('abc', SCANCODE_MAP.US))
        with self.assertRaises(ValueError):
            encode('ö')

    def test_de_layout(self):
        self.assertEqual(b'\x04', encode('a', SCANCODE_MAP.DE))
        self.assertEqual(b'\x05', encode('b', SCANCODE_MAP.DE))
        self.assertEqual(b'\x06', encode('c', SCANCODE_MAP.DE))
        self.assertEqual(b'\x07', encode('d', SCANCODE_MAP.DE))
        self.assertEqual(b'\x08', encode('e', SCANCODE_MAP.DE))
        self.assertEqual(b'\x09', encode('f', SCANCODE_MAP.DE))
        self.assertEqual(b'\x0a', encode('g', SCANCODE_MAP.DE))
        self.assertEqual(b'\x0b', encode('h', SCANCODE_MAP.DE))
        self.assertEqual(b'\x0c', encode('i', SCANCODE_MAP.DE))
        self.assertEqual(b'\x0d', encode('j', SCANCODE_MAP.DE))
        self.assertEqual(b'\x0e', encode('k', SCANCODE_MAP.DE))
        self.assertEqual(b'\x0f', encode('l', SCANCODE_MAP.DE))
        self.assertEqual(b'\x10', encode('m', SCANCODE_MAP.DE))
        self.assertEqual(b'\x11', encode('n', SCANCODE_MAP.DE))
        self.assertEqual(b'\x12', encode('o', SCANCODE_MAP.DE))
        self.assertEqual(b'\x13', encode('p', SCANCODE_MAP.DE))
        self.assertEqual(b'\x14', encode('q', SCANCODE_MAP.DE))
        self.assertEqual(b'\x15', encode('r', SCANCODE_MAP.DE))
        self.assertEqual(b'\x16', encode('s', SCANCODE_MAP.DE))
        self.assertEqual(b'\x17', encode('t', SCANCODE_MAP.DE))
        self.assertEqual(b'\x18', encode('u', SCANCODE_MAP.DE))
        self.assertEqual(b'\x19', encode('v', SCANCODE_MAP.DE))
        self.assertEqual(b'\x1a', encode('w', SCANCODE_MAP.DE))
        self.assertEqual(b'\x1b', encode('x', SCANCODE_MAP.DE))
        self.assertEqual(b'\x1d', encode('y', SCANCODE_MAP.DE))
        self.assertEqual(b'\x1c', encode('z', SCANCODE_MAP.DE))

        self.assertEqual(b'\x84', encode('A', SCANCODE_MAP.DE))
        self.assertEqual(b'\x85', encode('B', SCANCODE_MAP.DE))
        self.assertEqual(b'\x86', encode('C', SCANCODE_MAP.DE))
        self.assertEqual(b'\x87', encode('D', SCANCODE_MAP.DE))
        self.assertEqual(b'\x88', encode('E', SCANCODE_MAP.DE))
        self.assertEqual(b'\x89', encode('F', SCANCODE_MAP.DE))
        self.assertEqual(b'\x8a', encode('G', SCANCODE_MAP.DE))
        self.assertEqual(b'\x8b', encode('H', SCANCODE_MAP.DE))
        self.assertEqual(b'\x8c', encode('I', SCANCODE_MAP.DE))
        self.assertEqual(b'\x8d', encode('J', SCANCODE_MAP.DE))
        self.assertEqual(b'\x8e', encode('K', SCANCODE_MAP.DE))
        self.assertEqual(b'\x8f', encode('L', SCANCODE_MAP.DE))
        self.assertEqual(b'\x90', encode('M', SCANCODE_MAP.DE))
        self.assertEqual(b'\x91', encode('N', SCANCODE_MAP.DE))
        self.assertEqual(b'\x92', encode('O', SCANCODE_MAP.DE))
        self.assertEqual(b'\x93', encode('P', SCANCODE_MAP.DE))
        self.assertEqual(b'\x94', encode('Q', SCANCODE_MAP.DE))
        self.assertEqual(b'\x95', encode('R', SCANCODE_MAP.DE))
        self.assertEqual(b'\x96', encode('S', SCANCODE_MAP.DE))
        self.assertEqual(b'\x97', encode('T', SCANCODE_MAP.DE))
        self.assertEqual(b'\x98', encode('U', SCANCODE_MAP.DE))
        self.assertEqual(b'\x99', encode('V', SCANCODE_MAP.DE))
        self.assertEqual(b'\x9a', encode('W', SCANCODE_MAP.DE))
        self.assertEqual(b'\x9b', encode('X', SCANCODE_MAP.DE))
        self.assertEqual(b'\x9d', encode('Y', SCANCODE_MAP.DE))
        self.assertEqual(b'\x9c', encode('Z', SCANCODE_MAP.DE))

        self.assertEqual(b'\x27', encode('0', SCANCODE_MAP.DE))
        self.assertEqual(b'\x1e', encode('1', SCANCODE_MAP.DE))
        self.assertEqual(b'\x1f', encode('2', SCANCODE_MAP.DE))
        self.assertEqual(b'\x20', encode('3', SCANCODE_MAP.DE))
        self.assertEqual(b'\x21', encode('4', SCANCODE_MAP.DE))
        self.assertEqual(b'\x22', encode('5', SCANCODE_MAP.DE))
        self.assertEqual(b'\x23', encode('6', SCANCODE_MAP.DE))
        self.assertEqual(b'\x24', encode('7', SCANCODE_MAP.DE))
        self.assertEqual(b'\x25', encode('8', SCANCODE_MAP.DE))
        self.assertEqual(b'\x26', encode('9', SCANCODE_MAP.DE))

        self.assertEqual(b'\x2b', encode('\t', SCANCODE_MAP.DE))
        self.assertEqual(b'\x28', encode('\n', SCANCODE_MAP.DE))

        self.assertEqual(b'\x32', encode('#', SCANCODE_MAP.DE))
        self.assertEqual(b'\x30', encode('+', SCANCODE_MAP.DE))
        self.assertEqual(b'\x36', encode(',', SCANCODE_MAP.DE))
        self.assertEqual(b'\x38', encode('-', SCANCODE_MAP.DE))
        self.assertEqual(b'\x64', encode('<', SCANCODE_MAP.DE))
        self.assertEqual(b'\x35', encode('^', SCANCODE_MAP.DE))
        self.assertEqual(b'\x2c', encode(' ', SCANCODE_MAP.DE))
        self.assertEqual(b'\x2e', encode(u'´', SCANCODE_MAP.DE))
        self.assertEqual(b'\x2d', encode(u'ß', SCANCODE_MAP.DE))
        self.assertEqual(b'\x34', encode(u'ä', SCANCODE_MAP.DE))
        self.assertEqual(b'\x33', encode(u'ö', SCANCODE_MAP.DE))
        self.assertEqual(b'\x2f', encode(u'ü', SCANCODE_MAP.DE))

        self.assertEqual(b'\x9e', encode('!', SCANCODE_MAP.DE))
        self.assertEqual(b'\x9f', encode('"', SCANCODE_MAP.DE))
        self.assertEqual(b'\xa1', encode('$', SCANCODE_MAP.DE))
        self.assertEqual(b'\xa2', encode('%', SCANCODE_MAP.DE))
        self.assertEqual(b'\xa3', encode('&', SCANCODE_MAP.DE))
        self.assertEqual(b'\xb2', encode("'", SCANCODE_MAP.DE))
        self.assertEqual(b'\xa5', encode('(', SCANCODE_MAP.DE))
        self.assertEqual(b'\xa6', encode(')', SCANCODE_MAP.DE))
        self.assertEqual(b'\xb0', encode('*', SCANCODE_MAP.DE))
        self.assertEqual(b'\xa4', encode('/', SCANCODE_MAP.DE))
        self.assertEqual(b'\xb7', encode(':', SCANCODE_MAP.DE))
        self.assertEqual(b'\xb6', encode(';', SCANCODE_MAP.DE))
        self.assertEqual(b'\xa7', encode('=', SCANCODE_MAP.DE))
        self.assertEqual(b'\xe4', encode('>', SCANCODE_MAP.DE))
        self.assertEqual(b'\xad', encode('?', SCANCODE_MAP.DE))
        self.assertEqual(b'\xb8', encode('_', SCANCODE_MAP.DE))
        self.assertEqual(b'\xad', encode('`', SCANCODE_MAP.DE))
        self.assertEqual(b'\xa0', encode('§', SCANCODE_MAP.DE))
        self.assertEqual(b'\xb4', encode(u'Ä', SCANCODE_MAP.DE))
        self.assertEqual(b'\xb3', encode(u'Ö', SCANCODE_MAP.DE))
        self.assertEqual(b'\xaf', encode(u'Ü', SCANCODE_MAP.DE))

        self.assertEqual(
            b'\xb4\xb3\xaf', encode('ÄÖÜ', SCANCODE_MAP.DE))
        with self.assertRaises(ValueError):
            encode('@', SCANCODE_MAP.DE)
