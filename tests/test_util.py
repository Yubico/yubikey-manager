#  vim: set fileencoding=utf-8 :

import pytest
from yubikit.core import Tlv, bytes2int, int2bytes
from yubikit.core.otp import (
    calculate_crc,
    check_crc,
    modhex_decode,
    modhex_encode,
)
from yubikit.management import FORM_FACTOR


def test_bytes2int():
    assert bytes2int(b"\x57") == 0x57
    assert bytes2int(b"\x12\x34") == 0x1234
    assert bytes2int(b"\xca\xfe\xd0\x0d") == 0xCAFED00D


@pytest.mark.parametrize(
    ("value", "min_len", "expected"),
    [
        (0, 0, b""),
        (0, 3, b"\x00\x00\x00"),
        (0x1234, 4, b"\x00\x00\x12\x34"),
        (1 << 128, 1, b"\x01" + b"\x00" * 16),
    ],
)
def test_int2bytes_minimum_length(value, min_len, expected):
    assert int2bytes(value=value, min_len=min_len) == expected
    assert bytes2int(data=expected) == value


@pytest.mark.parametrize(("value", "min_len"), [(-1, 1), (1, -1)])
def test_int2bytes_rejects_negative_values(value, min_len):
    with pytest.raises(OverflowError):
        int2bytes(value, min_len)


def test_otp_crc():
    assert calculate_crc(data=b"") == 0xFFFF
    assert calculate_crc(data=b"123456789") == 0x6F91
    assert check_crc(data=b"123456789\x6e\x90")
    assert not check_crc(data=b"123456789\x6e\x91")


@pytest.mark.parametrize("value", ["c", "zz", "c!"])
def test_modhex_decode_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        modhex_decode(string=value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", b""),
        ("dteffuje", b"\x2d\x34\x4e\x83"),
        (
            "hknhfjbrjnlnldnhcujvddbikngjrtgh",
            b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56",
        ),
    ],
)
def test_modhex_decode(value, expected):
    assert modhex_decode(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"", ""),
        (b"\x2d\x34\x4e\x83", "dteffuje"),
        (
            b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56",
            "hknhfjbrjnlnldnhcujvddbikngjrtgh",
        ),
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


def test_tlv():
    assert Tlv(b"\xfe\6foobar") == Tlv(0xFE, b"foobar")

    tlv1 = Tlv(b"\0\5hello")
    tlv2 = Tlv(0xFE, b"")
    tlv3 = Tlv(0x12, b"hi" * 200)

    assert tlv1 == b"\0\5hello"
    assert tlv2 == b"\xfe\0"
    assert tlv3 == b"\x12\x82\x01\x90" + b"hi" * 200
    assert tlv1 + tlv2 + tlv3 == b"\0\5hello\xfe\0\x12\x82\x01\x90" + b"hi" * 200


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0x00, FORM_FACTOR.UNKNOWN),
        (0x01, FORM_FACTOR.USB_A_KEYCHAIN),
        (0x02, FORM_FACTOR.USB_A_NANO),
        (0x03, FORM_FACTOR.USB_C_KEYCHAIN),
        (0x04, FORM_FACTOR.USB_C_NANO),
        (0x05, FORM_FACTOR.USB_C_LIGHTNING),
        (0x99, FORM_FACTOR.UNKNOWN),
    ],
)
def test_form_factor_from_code(code, expected):
    assert FORM_FACTOR.from_code(code) == expected


def test_form_factor_from_code_rejects_invalid_type():
    with pytest.raises(ValueError):
        FORM_FACTOR.from_code("im a string")
