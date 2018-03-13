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
from ykman.scanmap import get_scan_codes


class TestScanMap(unittest.TestCase):

    def test_us_layout(self):
        self.assertEqual(b'\x04', get_scan_codes('a'))
        self.assertEqual(b'\x05', get_scan_codes('b'))
        self.assertEqual(b'\x06', get_scan_codes('c'))
        self.assertEqual(b'\x07', get_scan_codes('d'))
        self.assertEqual(b'\x08', get_scan_codes('e'))
        self.assertEqual(b'\x09', get_scan_codes('f'))
        self.assertEqual(b'\x0a', get_scan_codes('g'))
        self.assertEqual(b'\x0b', get_scan_codes('h'))
        self.assertEqual(b'\x0c', get_scan_codes('i'))
        self.assertEqual(b'\x0d', get_scan_codes('j'))
        self.assertEqual(b'\x0e', get_scan_codes('k'))
        self.assertEqual(b'\x0f', get_scan_codes('l'))
        self.assertEqual(b'\x10', get_scan_codes('m'))
        self.assertEqual(b'\x11', get_scan_codes('n'))
        self.assertEqual(b'\x12', get_scan_codes('o'))
        self.assertEqual(b'\x13', get_scan_codes('p'))
        self.assertEqual(b'\x14', get_scan_codes('q'))
        self.assertEqual(b'\x15', get_scan_codes('r'))
        self.assertEqual(b'\x16', get_scan_codes('s'))
        self.assertEqual(b'\x17', get_scan_codes('t'))
        self.assertEqual(b'\x18', get_scan_codes('u'))
        self.assertEqual(b'\x19', get_scan_codes('v'))
        self.assertEqual(b'\x1a', get_scan_codes('w'))
        self.assertEqual(b'\x1b', get_scan_codes('x'))
        self.assertEqual(b'\x1c', get_scan_codes('y'))
        self.assertEqual(b'\x1d', get_scan_codes('z'))

        self.assertEqual(b'\x84', get_scan_codes('A'))
        self.assertEqual(b'\x85', get_scan_codes('B'))
        self.assertEqual(b'\x86', get_scan_codes('C'))
        self.assertEqual(b'\x87', get_scan_codes('D'))
        self.assertEqual(b'\x88', get_scan_codes('E'))
        self.assertEqual(b'\x89', get_scan_codes('F'))
        self.assertEqual(b'\x8a', get_scan_codes('G'))
        self.assertEqual(b'\x8b', get_scan_codes('H'))
        self.assertEqual(b'\x8c', get_scan_codes('I'))
        self.assertEqual(b'\x8d', get_scan_codes('J'))
        self.assertEqual(b'\x8e', get_scan_codes('K'))
        self.assertEqual(b'\x8f', get_scan_codes('L'))
        self.assertEqual(b'\x90', get_scan_codes('M'))
        self.assertEqual(b'\x91', get_scan_codes('N'))
        self.assertEqual(b'\x92', get_scan_codes('O'))
        self.assertEqual(b'\x93', get_scan_codes('P'))
        self.assertEqual(b'\x94', get_scan_codes('Q'))
        self.assertEqual(b'\x95', get_scan_codes('R'))
        self.assertEqual(b'\x96', get_scan_codes('S'))
        self.assertEqual(b'\x97', get_scan_codes('T'))
        self.assertEqual(b'\x98', get_scan_codes('U'))
        self.assertEqual(b'\x99', get_scan_codes('V'))
        self.assertEqual(b'\x9a', get_scan_codes('W'))
        self.assertEqual(b'\x9b', get_scan_codes('X'))
        self.assertEqual(b'\x9c', get_scan_codes('Y'))
        self.assertEqual(b'\x9d', get_scan_codes('Z'))

        self.assertEqual(b'\x27', get_scan_codes('0'))
        self.assertEqual(b'\x1e', get_scan_codes('1'))
        self.assertEqual(b'\x1f', get_scan_codes('2'))
        self.assertEqual(b'\x20', get_scan_codes('3'))
        self.assertEqual(b'\x21', get_scan_codes('4'))
        self.assertEqual(b'\x22', get_scan_codes('5'))
        self.assertEqual(b'\x23', get_scan_codes('6'))
        self.assertEqual(b'\x24', get_scan_codes('7'))
        self.assertEqual(b'\x25', get_scan_codes('8'))
        self.assertEqual(b'\x26', get_scan_codes('9'))

        self.assertEqual(b'\x2b', get_scan_codes('\t'))
        self.assertEqual(b'\x28', get_scan_codes('\n'))

        self.assertEqual(b'\x9e', get_scan_codes('!'))
        self.assertEqual(b'\xb4', get_scan_codes('"'))
        self.assertEqual(b'\xa0', get_scan_codes('#'))
        self.assertEqual(b'\xa1', get_scan_codes('$'))
        self.assertEqual(b'\xa2', get_scan_codes('%'))
        self.assertEqual(b'\xa4', get_scan_codes('&'))
        self.assertEqual(b'\x34', get_scan_codes("'"))
        self.assertEqual(b'\xa6', get_scan_codes('('))
        self.assertEqual(b'\xa7', get_scan_codes(')'))
        self.assertEqual(b'\xa5', get_scan_codes('*'))
        self.assertEqual(b'\xae', get_scan_codes('+'))
        self.assertEqual(b'\x36', get_scan_codes(','))
        self.assertEqual(b'\x2d', get_scan_codes('-'))
        self.assertEqual(b'\x37', get_scan_codes('.'))
        self.assertEqual(b'\x38', get_scan_codes('/'))
        self.assertEqual(b'\xb3', get_scan_codes(':'))
        self.assertEqual(b'\x33', get_scan_codes(';'))
        self.assertEqual(b'\xb6', get_scan_codes('<'))
        self.assertEqual(b'\x2e', get_scan_codes('='))
        self.assertEqual(b'\xb7', get_scan_codes('>'))
        self.assertEqual(b'\xb8', get_scan_codes('?'))
        self.assertEqual(b'\x9f', get_scan_codes('@'))
        self.assertEqual(b'\x2f', get_scan_codes('['))
        self.assertEqual(b'\x32', get_scan_codes('\\'))
        self.assertEqual(b'\x30', get_scan_codes(']'))
        self.assertEqual(b'\xa3', get_scan_codes('^'))
        self.assertEqual(b'\xad', get_scan_codes('_'))
        self.assertEqual(b'\xaf', get_scan_codes('{'))
        self.assertEqual(b'\xb0', get_scan_codes('}'))
        self.assertEqual(b'\xb2', get_scan_codes('|'))
        self.assertEqual(b'\xb5', get_scan_codes('~'))

        self.assertEqual(b'\x04\x05\x06', get_scan_codes('abc'))
        with self.assertRaises(ValueError):
            get_scan_codes('ö')
