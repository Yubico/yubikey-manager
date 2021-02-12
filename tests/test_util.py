#  vim: set fileencoding=utf-8 :

from yubikit.core import Tlv, bytes2int
from yubikit.core.otp import modhex_encode, modhex_decode
from yubikit.management import FORM_FACTOR
from ykman.util import is_pkcs12, is_pem, parse_private_key, parse_certificates
from ykman.util import _parse_pkcs12_pyopenssl, _parse_pkcs12_cryptography
from ykman.otp import format_oath_code, generate_static_pw, time_challenge
from .util import open_file
from cryptography.hazmat.primitives.serialization import pkcs12
from OpenSSL import crypto

import unittest


class TestUtilityFunctions(unittest.TestCase):
    def test_bytes2int(self):
        self.assertEqual(0x57, bytes2int(b"\x57"))
        self.assertEqual(0x1234, bytes2int(b"\x12\x34"))
        self.assertEqual(0xCAFED00D, bytes2int(b"\xca\xfe\xd0\x0d"))

    def test_format_oath_code(self):
        self.assertEqual("000000", format_oath_code(b"\0" * 20))
        self.assertEqual("00000000", format_oath_code(b"\0" * 20, 8))
        self.assertEqual("345678", format_oath_code(b"\x00\xbc\x61\x4e" + b"\0" * 16))
        self.assertEqual(
            "34567890", format_oath_code(b"\x49\x96\x02\xd2" + b"\0" * 16, 8)
        )

    def test_generate_static_pw(self):
        for i in range(0, 38):
            self.assertRegex(
                generate_static_pw(i), "^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{%d}$" % i
            )

    def test_modhex_decode(self):
        self.assertEqual(b"", modhex_decode(""))
        self.assertEqual(b"\x2d\x34\x4e\x83", modhex_decode("dteffuje"))
        self.assertEqual(
            b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56",
            modhex_decode("hknhfjbrjnlnldnhcujvddbikngjrtgh"),
        )

    def test_modhex_encode(self):
        self.assertEqual("", modhex_encode(b""))
        self.assertEqual("dteffuje", modhex_encode(b"\x2d\x34\x4e\x83"))
        self.assertEqual(
            "hknhfjbrjnlnldnhcujvddbikngjrtgh",
            modhex_encode(
                b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6" b"\x0e\x8f\x22\x17\x9b\x58\xcd\x56"
            ),
        )

    def test_parse_tlvs(self):
        tlvs = Tlv.parse_list(b"\x00\x02\xd0\x0d\xa1\x00\xfe\x04\xfe\xed\xfa\xce")
        self.assertEqual(3, len(tlvs))

        self.assertEqual(0, tlvs[0].tag)
        self.assertEqual(2, tlvs[0].length)
        self.assertEqual(b"\xd0\x0d", tlvs[0].value)

        self.assertEqual(0xA1, tlvs[1].tag)
        self.assertEqual(0, tlvs[1].length)
        self.assertEqual(b"", tlvs[1].value)

        self.assertEqual(0xFE, tlvs[2].tag)
        self.assertEqual(4, tlvs[2].length)
        self.assertEqual(b"\xfe\xed\xfa\xce", tlvs[2].value)

    def test_time_challenge(self):
        self.assertEqual(b"\0" * 8, time_challenge(0))
        self.assertEqual(b"\x00\x00\x00\x00\x00\x06G\x82", time_challenge(12345678))
        self.assertEqual(
            b"\x00\x00\x00\x00\x02\xf2\xeaC", time_challenge(1484223461.2644958)
        )

    def test_tlv(self):
        self.assertEqual(Tlv(b"\xfe\6foobar"), Tlv(0xFE, b"foobar"))

        tlv1 = Tlv(b"\0\5hello")
        tlv2 = Tlv(0xFE, b"")
        tlv3 = Tlv(0x12, b"hi" * 200)

        self.assertEqual(b"\0\5hello", tlv1)
        self.assertEqual(b"\xfe\0", tlv2)
        self.assertEqual(b"\x12\x82\x01\x90" + b"hi" * 200, tlv3)

        self.assertEqual(
            b"\0\5hello\xfe\0\x12\x82\x01\x90" + b"hi" * 200, tlv1 + tlv2 + tlv3
        )

    def test_is_pkcs12(self):
        with self.assertRaises(TypeError):
            is_pkcs12("just a string")
        with self.assertRaises(TypeError):
            is_pkcs12(None)

        with open_file("rsa_2048_key.pem") as rsa_2048_key_pem:
            self.assertFalse(is_pkcs12(rsa_2048_key_pem.read()))

        with open_file("rsa_2048_key_encrypted.pem") as f:
            self.assertFalse(is_pkcs12(f.read()))

        with open_file("rsa_2048_cert.pem") as rsa_2048_cert_pem:
            self.assertFalse(is_pkcs12(rsa_2048_cert_pem.read()))

        with open_file("rsa_2048_key_cert.pfx") as rsa_2048_key_cert_pfx:
            data = rsa_2048_key_cert_pfx.read()
        self.assertTrue(is_pkcs12(data))
        parse_private_key(data, None)
        parse_certificates(data, None)

        with open_file(
            "rsa_2048_key_cert_encrypted.pfx"
        ) as rsa_2048_key_cert_encrypted_pfx:
            self.assertTrue(is_pkcs12(rsa_2048_key_cert_encrypted_pfx.read()))

    def test_parse_pkcs12(self):
        with open_file("rsa_2048_key_cert.pfx") as rsa_2048_key_cert_pfx:
            data = rsa_2048_key_cert_pfx.read()

        key1, certs1 = _parse_pkcs12_cryptography(pkcs12, data, None)
        key2, certs2 = _parse_pkcs12_pyopenssl(crypto, data, None)
        self.assertEqual(key1.private_numbers(), key2.private_numbers())
        self.assertEqual(1, len(certs1))
        self.assertEqual(certs1, certs2)

    def test_is_pem(self):
        self.assertFalse(is_pem(b"just a byte string"))
        self.assertFalse(is_pem(None))

        with open_file("rsa_2048_key.pem") as rsa_2048_key_pem:
            self.assertTrue(is_pem(rsa_2048_key_pem.read()))

        with open_file("rsa_2048_key_encrypted.pem") as f:
            self.assertTrue(is_pem(f.read()))

        with open_file("rsa_2048_cert.pem") as rsa_2048_cert_pem:
            self.assertTrue(is_pem(rsa_2048_cert_pem.read()))

        with open_file("rsa_2048_key_cert.pfx") as rsa_2048_key_cert_pfx:
            self.assertFalse(is_pem(rsa_2048_key_cert_pfx.read()))

        with open_file("rsa_2048_cert_metadata.pem") as f:
            self.assertTrue(is_pem(f.read()))

        with open_file(
            "rsa_2048_key_cert_encrypted.pfx"
        ) as rsa_2048_key_cert_encrypted_pfx:
            self.assertFalse(is_pem(rsa_2048_key_cert_encrypted_pfx.read()))

    def test_form_factor_from_code(self):
        self.assertEqual(FORM_FACTOR.UNKNOWN, FORM_FACTOR.from_code(None))
        with self.assertRaises(ValueError):
            FORM_FACTOR.from_code("im a string")
        self.assertEqual(FORM_FACTOR.UNKNOWN, FORM_FACTOR.from_code(0x00))
        self.assertEqual(FORM_FACTOR.USB_A_KEYCHAIN, FORM_FACTOR.from_code(0x01))
        self.assertEqual(FORM_FACTOR.USB_A_NANO, FORM_FACTOR.from_code(0x02))
        self.assertEqual(FORM_FACTOR.USB_C_KEYCHAIN, FORM_FACTOR.from_code(0x03))
        self.assertEqual(FORM_FACTOR.USB_C_NANO, FORM_FACTOR.from_code(0x04))
        self.assertEqual(FORM_FACTOR.USB_C_LIGHTNING, FORM_FACTOR.from_code(0x05))
        self.assertEqual(FORM_FACTOR.UNKNOWN, FORM_FACTOR.from_code(0x99))
