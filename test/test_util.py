#  vim: set fileencoding=utf-8 :

from ykman.util import (bytes2int, format_code, generate_static_pw,
                        hmac_shorten_key, modhex_decode, modhex_encode,
                        parse_tlvs, parse_truncated, time_challenge, Tlv,
                        is_pkcs12, is_pem, FORM_FACTOR)
from .util import open_file
import unittest


if not getattr(unittest.TestCase, 'assertRegex', None):
    # Python 2.7 can use assertRegexpMatches
    unittest.TestCase.assertRegex = unittest.TestCase.assertRegexpMatches


class TestUtilityFunctions(unittest.TestCase):

    def test_bytes2int(self):
        self.assertEqual(0x57, bytes2int(b'\x57'))
        self.assertEqual(0x1234, bytes2int(b'\x12\x34'))
        self.assertEqual(0xcafed00d, bytes2int(b'\xca\xfe\xd0\x0d'))

    def test_format_code(self):
        self.assertEqual('000000', format_code(0))
        self.assertEqual('00000000', format_code(0, 8))
        self.assertEqual('345678', format_code(12345678))
        self.assertEqual('34567890', format_code(1234567890, 8))
        self.assertEqual('22222', format_code(0, steam=True))
        self.assertEqual('DVNKW', format_code(1234567890, steam=True))
        self.assertEqual('KDNYM', format_code(9999999999, steam=True))

    def test_generate_static_pw(self):
        for l in range(0, 38):
            self.assertRegex(
                generate_static_pw(l),
                '^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{%d}$' % l)

    def test_hmac_shorten_key(self):
        self.assertEqual(b'short', hmac_shorten_key(b'short', 'sha1'))
        self.assertEqual(b'x'*64, hmac_shorten_key(b'x'*64, 'sha1'))
        self.assertEqual(
            b'0\xec\xd3\xf4\xb5\xcej\x1a\xc6x'
            b'\x15\xdb\xa1\xfb\x7f\x9f\xff\x00`\x14',
            hmac_shorten_key(b'l'*65, 'sha1')
        )
        self.assertEqual(b'x'*64, hmac_shorten_key(b'x'*64, 'sha256'))
        self.assertEqual(
            b'l\xf9\x08}"vi\xbcj\xa9\nlkQ\x81\xd9`'
            b'\xbb\x88\xe9L4\x0b\xbd?\x07s/K\xae\xb9L',
            hmac_shorten_key(b'l'*65, 'sha256')
        )

    def test_modhex_decode(self):
        self.assertEqual(b'', modhex_decode(''))
        self.assertEqual(b'\x2d\x34\x4e\x83', modhex_decode('dteffuje'))
        self.assertEqual(
            b'\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56',
            modhex_decode('hknhfjbrjnlnldnhcujvddbikngjrtgh')
        )

    def test_modhex_encode(self):
        self.assertEqual('', modhex_encode(b''))
        self.assertEqual('dteffuje', modhex_encode(b'\x2d\x34\x4e\x83'))
        self.assertEqual(
            'hknhfjbrjnlnldnhcujvddbikngjrtgh',
            modhex_encode(b'\x69\xb6\x48\x1c\x8b\xab\xa2\xb6'
                          b'\x0e\x8f\x22\x17\x9b\x58\xcd\x56')
        )

    def test_parse_tlvs(self):
        tlvs = parse_tlvs(b'\x00\x02\xd0\x0d\xa1\x00\xfe\x04\xfe\xed\xfa\xce')
        self.assertEqual(3, len(tlvs))

        self.assertEqual(0, tlvs[0].tag)
        self.assertEqual(2, tlvs[0].length)
        self.assertEqual(b'\xd0\x0d', tlvs[0].value)

        self.assertEqual(0xa1, tlvs[1].tag)
        self.assertEqual(0, tlvs[1].length)
        self.assertEqual(b'', tlvs[1].value)

        self.assertEqual(0xfe, tlvs[2].tag)
        self.assertEqual(4, tlvs[2].length)
        self.assertEqual(b'\xfe\xed\xfa\xce', tlvs[2].value)

    def test_parse_truncated(self):
        self.assertEqual(0x01020304, parse_truncated(b'\1\2\3\4'))
        self.assertEqual(0xdeadbeef & 0x7fffffff,
                         parse_truncated(b'\xde\xad\xbe\xef'))

    def test_time_challenge(self):
        self.assertEqual(b'\0'*8, time_challenge(0))
        self.assertEqual(b'\x00\x00\x00\x00\x00\x06G\x82',
                         time_challenge(12345678))
        self.assertEqual(b'\x00\x00\x00\x00\x02\xf2\xeaC',
                         time_challenge(1484223461.2644958))

    def test_tlv(self):
        self.assertEqual(Tlv(b'\xfe\6foobar'), Tlv(0xfe, b'foobar'))

        tlv1 = Tlv(b'\0\5hello')
        tlv2 = Tlv(0xff, b'')
        tlv3 = Tlv(0x12, b'hi'*200)

        self.assertEqual(b'\0\5hello', tlv1)
        self.assertEqual(b'\xff\0', tlv2)
        self.assertEqual(b'\x12\x82\x01\x90' + b'hi'*200, tlv3)

        self.assertEqual(b'\0\5hello\xff\0\x12\x82\x01\x90' + b'hi'*200,
                         tlv1 + tlv2 + tlv3)

    def test_is_pkcs12(self):
        self.assertFalse(is_pkcs12('just a string'))
        self.assertFalse(is_pkcs12(None))

        with open_file('rsa_2048_key.pem') as rsa_2048_key_pem:
            self.assertFalse(is_pkcs12(rsa_2048_key_pem.read()))

        with open_file('rsa_2048_key_encrypted.pem') as f:
            self.assertFalse(is_pkcs12(f.read()))

        with open_file('rsa_2048_cert.pem') as rsa_2048_cert_pem:
            self.assertFalse(is_pkcs12(rsa_2048_cert_pem.read()))

        with open_file('rsa_2048_key_cert.pfx') as rsa_2048_key_cert_pfx:
            self.assertTrue(is_pkcs12(rsa_2048_key_cert_pfx.read()))

        with open_file(
            'rsa_2048_key_cert_encrypted.pfx') as \
                rsa_2048_key_cert_encrypted_pfx:
            self.assertTrue(is_pkcs12(rsa_2048_key_cert_encrypted_pfx.read()))

    def test_is_pem(self):
        self.assertFalse(is_pem(b'just a byte string'))
        self.assertFalse(is_pem(None))

        with open_file('rsa_2048_key.pem') as rsa_2048_key_pem:
            self.assertTrue(is_pem(rsa_2048_key_pem.read()))

        with open_file('rsa_2048_key_encrypted.pem') as f:
            self.assertTrue(is_pem(f.read()))

        with open_file('rsa_2048_cert.pem') as rsa_2048_cert_pem:
            self.assertTrue(is_pem(rsa_2048_cert_pem.read()))

        with open_file('rsa_2048_key_cert.pfx') as rsa_2048_key_cert_pfx:
            self.assertFalse(is_pem(rsa_2048_key_cert_pfx.read()))

        with open_file('rsa_2048_cert_metadata.pem') as f:
            self.assertTrue(is_pem(f.read()))

        with open_file(
            'rsa_2048_key_cert_encrypted.pfx') as \
                rsa_2048_key_cert_encrypted_pfx:
            self.assertFalse(is_pem(rsa_2048_key_cert_encrypted_pfx.read()))

    def test_form_factor_from_code(self):
        self.assertEqual(FORM_FACTOR.UNKNOWN, FORM_FACTOR.from_code(None))
        with self.assertRaises(ValueError):
            FORM_FACTOR.from_code('im a string')
        self.assertEqual(FORM_FACTOR.UNKNOWN, FORM_FACTOR.from_code(0x00))
        self.assertEqual(
            FORM_FACTOR.USB_A_KEYCHAIN, FORM_FACTOR.from_code(0x01))
        self.assertEqual(FORM_FACTOR.USB_A_NANO, FORM_FACTOR.from_code(0x02))
        self.assertEqual(
            FORM_FACTOR.USB_C_KEYCHAIN, FORM_FACTOR.from_code(0x03))
        self.assertEqual(FORM_FACTOR.USB_C_NANO, FORM_FACTOR.from_code(0x04))
        self.assertEqual(FORM_FACTOR.USB_C_LIGHTNING,
                         FORM_FACTOR.from_code(0x05))
        self.assertEqual(FORM_FACTOR.UNKNOWN, FORM_FACTOR.from_code(0x06))
