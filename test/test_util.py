#  vim: set fileencoding=utf-8 :

import pytest
import re

from ykman.util import (bytes2int, format_code, generate_static_pw,
                        hmac_shorten_key, modhex_decode, modhex_encode,
                        parse_tlvs, parse_truncated, time_challenge, Tlv,
                        is_pkcs12, is_pem, FORM_FACTOR)
from .util import open_file


class TestUtilityFunctions(object):

    def test_bytes2int(self):
        assert 0x57 == bytes2int(b'\x57')
        assert 0x1234 == bytes2int(b'\x12\x34')
        assert 0xcafed00d == bytes2int(b'\xca\xfe\xd0\x0d')

    def test_format_code(self):
        assert '000000' == format_code(0)
        assert '00000000' == format_code(0, 8)
        assert '345678' == format_code(12345678)
        assert '34567890' == format_code(1234567890, 8)
        assert '22222' == format_code(0, steam=True)
        assert 'DVNKW' == format_code(1234567890, steam=True)
        assert 'KDNYM' == format_code(9999999999, steam=True)

    def test_generate_static_pw(self):
        for l in range(0, 38):
            assert re.match(
                '^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{%d}$' % l,
                generate_static_pw(l))

    def test_hmac_shorten_key(self):
        assert b'short', hmac_shorten_key(b'short' == 'sha1')
        assert b'x'*64, hmac_shorten_key(b'x'*64 == 'sha1')
        assert(
            b'0\xec\xd3\xf4\xb5\xcej\x1a\xc6x'
            b'\x15\xdb\xa1\xfb\x7f\x9f\xff\x00`\x14'
            ==
            hmac_shorten_key(b'l'*65, 'sha1'))
        assert b'x'*64, hmac_shorten_key(b'x'*64 == 'sha256')
        assert(
            b'l\xf9\x08}"vi\xbcj\xa9\nlkQ\x81\xd9`'
            b'\xbb\x88\xe9L4\x0b\xbd?\x07s/K\xae\xb9L'
            ==
            hmac_shorten_key(b'l'*65, 'sha256'))

    def test_modhex_decode(self):
        assert b'' == modhex_decode('')
        assert b'\x2d\x34\x4e\x83' == modhex_decode('dteffuje')
        assert(
            b'\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56'
            ==
            modhex_decode('hknhfjbrjnlnldnhcujvddbikngjrtgh'))

    def test_modhex_encode(self):
        assert '' == modhex_encode(b'')
        assert 'dteffuje' == modhex_encode(b'\x2d\x34\x4e\x83')
        assert(
            'hknhfjbrjnlnldnhcujvddbikngjrtgh'
            ==
            modhex_encode(b'\x69\xb6\x48\x1c\x8b\xab\xa2\xb6'
                          b'\x0e\x8f\x22\x17\x9b\x58\xcd\x56'))

    def test_parse_tlvs(self):
        tlvs = parse_tlvs(b'\x00\x02\xd0\x0d\xa1\x00\xfe\x04\xfe\xed\xfa\xce')
        assert 3 == len(tlvs)

        assert 0 == tlvs[0].tag
        assert 2 == tlvs[0].length
        assert b'\xd0\x0d' == tlvs[0].value

        assert 0xa1 == tlvs[1].tag
        assert 0 == tlvs[1].length
        assert b'' == tlvs[1].value

        assert 0xfe == tlvs[2].tag
        assert 4 == tlvs[2].length
        assert b'\xfe\xed\xfa\xce' == tlvs[2].value

    def test_parse_truncated(self):
        assert 0x01020304 == parse_truncated(b'\1\2\3\4')
        assert 0xdeadbeef & 0x7fffffff == parse_truncated(b'\xde\xad\xbe\xef')

    def test_time_challenge(self):
        assert b'\0'*8 == time_challenge(0)
        assert b'\x00\x00\x00\x00\x00\x06G\x82' == time_challenge(12345678)
        assert(b'\x00\x00\x00\x00\x02\xf2\xeaC'
               == time_challenge(1484223461.2644958))

    def test_tlv(self):
        assert Tlv(b'\xfe\6foobar'), Tlv(0xfe == b'foobar')

        tlv1 = Tlv(b'\0\5hello')
        tlv2 = Tlv(0xff, b'')
        tlv3 = Tlv(0x12, b'hi'*200)

        assert b'\0\5hello' == tlv1
        assert b'\xff\0' == tlv2
        assert b'\x12\x82\x01\x90' + b'hi'*200 == tlv3

        assert(b'\0\5hello\xff\0\x12\x82\x01\x90' + b'hi'*200
               == tlv1 + tlv2 + tlv3)

    def test_is_pkcs12(self):
        assert not is_pkcs12('just a string')
        assert not is_pkcs12(None)

        with open_file('rsa_2048_key.pem') as rsa_2048_key_pem:
            assert not is_pkcs12(rsa_2048_key_pem.read())

        with open_file('rsa_2048_key_encrypted.pem') as f:
            assert not is_pkcs12(f.read())

        with open_file('rsa_2048_cert.pem') as rsa_2048_cert_pem:
            assert not is_pkcs12(rsa_2048_cert_pem.read())

        with open_file('rsa_2048_key_cert.pfx') as rsa_2048_key_cert_pfx:
            assert is_pkcs12(rsa_2048_key_cert_pfx.read())

        with open_file(
            'rsa_2048_key_cert_encrypted.pfx') as \
                rsa_2048_key_cert_encrypted_pfx:
            assert is_pkcs12(rsa_2048_key_cert_encrypted_pfx.read())

    def test_is_pem(self):
        assert not is_pem(b'just a byte string')
        assert not is_pem(None)

        with open_file('rsa_2048_key.pem') as rsa_2048_key_pem:
            assert is_pem(rsa_2048_key_pem.read())

        with open_file('rsa_2048_key_encrypted.pem') as f:
            assert is_pem(f.read())

        with open_file('rsa_2048_cert.pem') as rsa_2048_cert_pem:
            assert is_pem(rsa_2048_cert_pem.read())

        with open_file('rsa_2048_key_cert.pfx') as rsa_2048_key_cert_pfx:
            assert not is_pem(rsa_2048_key_cert_pfx.read())

        with open_file('rsa_2048_cert_metadata.pem') as f:
            assert is_pem(f.read())

        with open_file(
            'rsa_2048_key_cert_encrypted.pfx') as \
                rsa_2048_key_cert_encrypted_pfx:
            assert not is_pem(rsa_2048_key_cert_encrypted_pfx.read())

    def test_form_factor_from_code(self):
        assert FORM_FACTOR.UNKNOWN == FORM_FACTOR.from_code(None)
        with pytest.raises(ValueError):
            FORM_FACTOR.from_code('im a string')
        assert FORM_FACTOR.UNKNOWN == FORM_FACTOR.from_code(0x00)
        assert FORM_FACTOR.USB_A_KEYCHAIN == FORM_FACTOR.from_code(0x01)
        assert FORM_FACTOR.USB_A_NANO == FORM_FACTOR.from_code(0x02)
        assert FORM_FACTOR.USB_C_KEYCHAIN == FORM_FACTOR.from_code(0x03)
        assert FORM_FACTOR.USB_C_NANO == FORM_FACTOR.from_code(0x04)
        assert FORM_FACTOR.USB_C_LIGHTNING == FORM_FACTOR.from_code(0x05)
        assert FORM_FACTOR.UNKNOWN == FORM_FACTOR.from_code(0x06)
