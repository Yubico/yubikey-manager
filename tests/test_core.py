from yubikit.core import Tlv, Oid, bytes2int, int2bytes
import pytest

OID_TESTS = {
    "1.2.840.10045.3.1.7": b"\x2a\x86\x48\xce\x3d\x03\x01\x07",  # SECP256R1
    "1.3.132.0.10": b"\x2b\x81\x04\x00\x0a",  # SECP256K1
    "1.3.132.0.34": b"\x2b\x81\x04\x00\x22",  # SECP384R1
    "1.3.132.0.35": b"\x2b\x81\x04\x00\x23",  # SECP521R1
    "1.3.36.3.3.2.8.1.1.7": b"\x2b\x24\x03\x03\x02\x08\x01\x01\x07",  # BrainpoolP256R1
    "1.3.36.3.3.2.8.1.1.11": b"\x2b\x24\x03\x03\x02\x08\x01\x01\x0b",  # BrainpoolP384R1
    "1.3.36.3.3.2.8.1.1.13": b"\x2b\x24\x03\x03\x02\x08\x01\x01\x0d",  # BrainpoolP512R1
    "1.3.6.1.4.1.3029.1.5.1": b"\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01",  # X25519
    "1.3.6.1.4.1.11591.15.1": b"\x2b\x06\x01\x04\x01\xda\x47\x0f\x01",  # Ed25519
}


@pytest.mark.parametrize("oid_str, oid_bytes", OID_TESTS.items())
def test_oid_conversion(oid_str, oid_bytes):
    oid = Oid.from_string(oid_str)
    assert oid == Oid(oid_bytes)
    assert oid.dotted_string == oid_str
    assert bytes(oid) == oid_bytes

    # Test round-trip conversion
    assert Oid(bytes(oid)) == oid
    assert Oid.from_string(oid.dotted_string) == oid

    # Test that the bytes representation matches the expected bytes
    assert bytes(oid) == oid_bytes


@pytest.mark.parametrize("value", (b"", None))
def test_empty_tlv(value):
    # Test that an empty Tlv can be created and serialized
    tlv = Tlv(0x01, value)
    assert tlv.tag == 0x01
    assert tlv.length == 0
    assert tlv.value == b""
    assert bytes(tlv) == b"\x01\x00"


# Some sample TLV data for testing
TLV_TESTS = {
    "0100": Tlv(0x01, b""),
    "020101": Tlv(0x02, b"\x01"),
    "03020203": Tlv(0x03, b"\x02\x03"),
    "0403020101": Tlv(0x04, Tlv(0x02, b"\x01")),
}


@pytest.mark.parametrize("data, expected_tlv", TLV_TESTS.items())
def test_tlv_parsing(data, expected_tlv):
    data = bytes.fromhex(data)

    # Test parsing TLV data
    tlv = Tlv(data)
    assert tlv == expected_tlv

    # Test that the serialized TLV matches the original data
    assert bytes(tlv) == data

    # Test that unpacking the TLV gives the correct tag, length, and value
    assert tlv.tag == expected_tlv.tag
    assert tlv.length == expected_tlv.length
    assert tlv.value == expected_tlv.value


@pytest.mark.parametrize("ln", (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000))
def test_tlv_length_boundries(ln):
    data = b"\xcc" * ln
    tlv = Tlv(0x01, data)
    assert tlv.tag == 0x01
    assert tlv.length == ln
    assert tlv.value == data
    assert tlv == Tlv(tlv)


def test_tlv_multibyte_tag():
    # Test that multi-byte tags are handled correctly
    tlv = Tlv(0x7F49, b"test")
    assert tlv.tag == 0x7F49
    assert tlv.length == 4
    assert tlv.value == b"test"
    assert bytes(tlv) == b"\x7f\x49\x04test"

    # Test that the TLV can be parsed back correctly
    parsed_tlv = Tlv(bytes(tlv))
    assert parsed_tlv == tlv

    # Test invalid multi-byte tag
    with pytest.raises(ValueError):
        Tlv(0xFFFF, b"invalid")


@pytest.mark.parametrize("n", (0, 1, 0xFF, 0x100, 0xFFFF, 0x10000))
def test_int2bytes(n):
    assert bytes2int(int2bytes(n)) == n
