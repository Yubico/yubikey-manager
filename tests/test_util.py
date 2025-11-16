#  vim: set fileencoding=utf-8 :

import re

import pytest

from ykman import __version__ as version
from ykman.otp import format_oath_code, generate_static_pw, time_challenge
from ykman.util import (
    _parse_pkcs12,
    is_pem,
    is_pkcs12,
    parse_certificates,
    parse_private_key,
)
from yubikit.core import InvalidPinError, Tlv, bytes2int
from yubikit.core.otp import modhex_decode, modhex_encode
from yubikit.management import FORM_FACTOR

from .util import open_file


def test_invalid_pin_exception_value_error():
    # Fail if InvalidPinError still inherits ValueError in ykman 6.0
    if int(version.split(".")[0]) != 5:
        assert not isinstance(InvalidPinError(3), ValueError)


def test_bytes2int():
    assert bytes2int(b"\x57") == 0x57
    assert bytes2int(b"\x12\x34") == 0x1234
    assert bytes2int(b"\xca\xfe\xd0\x0d") == 0xCAFED00D


@pytest.mark.parametrize(
    ("payload", "digits", "expected"),
    [
        (b"\0" * 20, None, "000000"),
        (b"\0" * 20, 8, "00000000"),
        (b"\x00\xbc\x61\x4e" + b"\0" * 16, None, "345678"),
        (b"\x49\x96\x02\xd2" + b"\0" * 16, 8, "34567890"),
    ],
)
def test_format_oath_code(payload, digits, expected):
    if digits is None:
        assert format_oath_code(payload) == expected
    else:
        assert format_oath_code(payload, digits) == expected


def test_generate_static_pw():
    template = r"^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{%d}$"
    for length in range(0, 38):
        pattern = re.compile(template % length)
        assert pattern.fullmatch(
            generate_static_pw(length)
        ), f"Length {length} failed regex check"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", b""),
        ("dteffuje", b"\x2d\x34\x4e\x83"),
        ("hknhfjbrjnlnldnhcujvddbikngjrtgh", b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56"),
    ],
)
def test_modhex_decode(value, expected):
    assert modhex_decode(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"", ""),
        (b"\x2d\x34\x4e\x83", "dteffuje"),
        (b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56", "hknhfjbrjnlnldnhcujvddbikngjrtgh"),
    ],
)
def test_modhex_encode(value, expected):
    assert modhex_encode(value) == expected


def test_parse_tlvs():
    tlvs = Tlv.parse_list(b"\x00\x02\xd0\x0d\xa1\x00\xfe\x04\xfe\xed\xfa\xce")
    assert len(tlvs) == 3

    assert tlvs[0].tag == 0
    assert tlvs[0].length == 2
    assert tlvs[0].value == b"\xd0\x0d"

    assert tlvs[1].tag == 0xA1
    assert tlvs[1].length == 0
    assert tlvs[1].value == b""

    assert tlvs[2].tag == 0xFE
    assert tlvs[2].length == 4
    assert tlvs[2].value == b"\xfe\xed\xfa\xce"


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (0, b"\0" * 8),
        (12345678, b"\x00\x00\x00\x00\x00\x06G\x82"),
        (1484223461.2644958, b"\x00\x00\x00\x00\x02\xf2\xeaC"),
    ],
)
def test_time_challenge(timestamp, expected):
    assert time_challenge(timestamp) == expected


def test_tlv():
    assert Tlv(b"\xfe\6foobar") == Tlv(0xFE, b"foobar")

    tlv1 = Tlv(b"\0\5hello")
    tlv2 = Tlv(0xFE, b"")
    tlv3 = Tlv(0x12, b"hi" * 200)

    assert tlv1 == b"\0\5hello"
    assert tlv2 == b"\xfe\0"
    assert tlv3 == b"\x12\x82\x01\x90" + b"hi" * 200
    assert tlv1 + tlv2 + tlv3 == b"\0\5hello\xfe\0\x12\x82\x01\x90" + b"hi" * 200


def test_is_pkcs12():
    with pytest.raises(TypeError):
        is_pkcs12(None)

    with open_file("rsa_2048_key.pem") as rsa_2048_key_pem:
        assert not is_pkcs12(rsa_2048_key_pem.read())

    with open_file("rsa_2048_key_encrypted.pem") as f:
        assert not is_pkcs12(f.read())

    with open_file("rsa_2048_cert.pem") as rsa_2048_cert_pem:
        assert not is_pkcs12(rsa_2048_cert_pem.read())

    with open_file("rsa_2048_key_cert.pfx") as rsa_2048_key_cert_pfx:
        data = rsa_2048_key_cert_pfx.read()
    assert is_pkcs12(data)
    parse_private_key(data, None)
    parse_certificates(data, None)

    with open_file("rsa_2048_key_cert_encrypted.pfx") as encrypted_pfx:
        assert is_pkcs12(encrypted_pfx.read())


def test_parse_pkcs12():
    with open_file("rsa_2048_key_cert.pfx") as rsa_2048_key_cert_pfx:
        data = rsa_2048_key_cert_pfx.read()

    key, certs = _parse_pkcs12(data, None)
    assert key is not None
    assert len(certs) == 1


def test_is_pem():
    assert not is_pem(b"just a byte string")
    assert not is_pem(None)

    with open_file("rsa_2048_key.pem") as rsa_2048_key_pem:
        assert is_pem(rsa_2048_key_pem.read())

    with open_file("rsa_2048_key_encrypted.pem") as f:
        assert is_pem(f.read())

    with open_file("rsa_2048_cert.pem") as rsa_2048_cert_pem:
        assert is_pem(rsa_2048_cert_pem.read())

    with open_file("rsa_2048_key_cert.pfx") as rsa_2048_key_cert_pfx:
        assert not is_pem(rsa_2048_key_cert_pfx.read())

    with open_file("rsa_2048_cert_metadata.pem") as f:
        assert is_pem(f.read())

    with open_file("rsa_2048_key_cert_encrypted.pfx") as encrypted_pfx:
        assert not is_pem(encrypted_pfx.read())


def test_form_factor_from_code():
    with pytest.raises(ValueError):
        FORM_FACTOR.from_code("im a string")  # type: ignore[arg-type]

    assert FORM_FACTOR.from_code(0x00) == FORM_FACTOR.UNKNOWN
    assert FORM_FACTOR.from_code(0x01) == FORM_FACTOR.USB_A_KEYCHAIN
    assert FORM_FACTOR.from_code(0x02) == FORM_FACTOR.USB_A_NANO
    assert FORM_FACTOR.from_code(0x03) == FORM_FACTOR.USB_C_KEYCHAIN
    assert FORM_FACTOR.from_code(0x04) == FORM_FACTOR.USB_C_NANO
    assert FORM_FACTOR.from_code(0x05) == FORM_FACTOR.USB_C_LIGHTNING
    assert FORM_FACTOR.from_code(0x99) == FORM_FACTOR.UNKNOWN
