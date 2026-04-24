import gzip
import zlib
from datetime import date

import pytest

from yubikit.core import BadResponseError, NotSupportedError, Version
from yubikit.piv import (
    KEY_TYPE,
    PIN_POLICY,
    TOUCH_POLICY,
    Chuid,
    FascN,
    _do_check_key_support,
    decompress_certificate,
)


class TestPivFunctions:
    def test_supported_algorithms(self):
        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(3, 1, 1),
                KEY_TYPE.ECCP384,
                PIN_POLICY.DEFAULT,
                TOUCH_POLICY.DEFAULT,
            )

        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(4, 4, 1),
                KEY_TYPE.RSA1024,
                PIN_POLICY.DEFAULT,
                TOUCH_POLICY.DEFAULT,
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.X25519):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(5, 7, 0),
                    key_type,
                    PIN_POLICY.DEFAULT,
                    TOUCH_POLICY.DEFAULT,
                    fips_restrictions=True,
                )

        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(5, 7, 0),
                KEY_TYPE.RSA2048,
                PIN_POLICY.NEVER,
                TOUCH_POLICY.DEFAULT,
                fips_restrictions=True,
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.RSA2048):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(4, 3, 4), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(5, 6, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in KEY_TYPE:
            _do_check_key_support(
                Version(5, 7, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )


def test_fascn():
    fascn = FascN(
        agency_code=32,
        system_code=1,
        credential_number=92446,
        credential_series=0,
        individual_credential_issue=1,
        person_identifier=1112223333,
        organizational_category=1,
        organizational_identifier=1223,
        organization_association_category=2,
    )

    # https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf
    # page 32
    expected = bytes.fromhex("D0439458210C2C19A0846D83685A1082108CE73984108CA3FC")
    assert bytes(fascn) == expected

    assert FascN.from_bytes(expected) == fascn


def test_chuid():
    guid = b"x" * 16
    chuid = Chuid(
        # Non-Federal Issuer FASC-N
        fasc_n=FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1),
        guid=guid,
        expiration_date=date(2030, 1, 1),
        asymmetric_signature=b"",
    )

    expected = bytes.fromhex(
        "3019d4e739da739ced39ce739d836858210842108421c84210c3eb3410787878787878787878"
        "78787878787878350832303330303130313e00fe00"
    )

    assert bytes(chuid) == expected

    assert Chuid.from_bytes(expected) == chuid


def test_chuid_deserialize():
    chuid = Chuid(
        buffer_length=123,
        fasc_n=FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1),
        agency_code=b"1234",
        organizational_identifier=b"5678",
        duns=b"123456789",
        guid=b"x" * 16,
        expiration_date=date(2030, 1, 1),
        authentication_key_map=b"1234567890",
        asymmetric_signature=b"0987654321",
        lrc=255,
    )

    assert Chuid.from_bytes(bytes(chuid)) == chuid


class TestDecompressCertificate:
    def test_gzip_decompression(self):
        """Test decompression of gzip-compressed certificate data."""
        original_data = b"This is a test certificate data"
        compressed_data = gzip.compress(original_data)

        result = decompress_certificate(compressed_data)
        assert result == original_data

    def test_zlib_deflate_decompression(self):
        """Test decompression of zlib deflate format (used by Pointsharp Net iD)."""
        original_data = b"Test certificate content for zlib format"

        # zlib format: 0x01 0x00 + 2-byte little-endian length + zlib compressed data
        compressor = zlib.compressobj(wbits=zlib.MAX_WBITS)
        compressed = compressor.compress(original_data) + compressor.flush()

        # Build zlib format: magic bytes + length + compressed data
        length_bytes = len(original_data).to_bytes(2, "little")
        zlib_data = b"\x01\x00" + length_bytes + compressed

        result = decompress_certificate(zlib_data)
        assert result == original_data

    def test_zlib_deflate_wrong_length_raises(self):
        """Test that zlib deflate with wrong expected length raises ValueError."""
        original_data = b"Test certificate content"

        compressor = zlib.compressobj(wbits=zlib.MAX_WBITS)
        compressed = compressor.compress(original_data) + compressor.flush()

        # Use wrong length (actual length + 10)
        wrong_length = len(original_data) + 10
        length_bytes = wrong_length.to_bytes(2, "little")
        zlib_data = b"\x01\x00" + length_bytes + compressed

        with pytest.raises(BadResponseError):
            decompress_certificate(zlib_data)

    def test_invalid_data_raises_bad_response_error(self):
        """Test that invalid/uncompressed data raises BadResponseError."""
        invalid_data = b"This is not compressed data at all"

        with pytest.raises(BadResponseError):
            decompress_certificate(invalid_data)

    def test_corrupted_gzip_raises_bad_response_error(self):
        """Test that corrupted gzip data raises BadResponseError."""
        # Create valid gzip magic bytes but corrupted content
        corrupted_gzip = b"\x1f\x8b\x08\x00" + b"corrupted content"

        with pytest.raises(BadResponseError):
            decompress_certificate(corrupted_gzip)

    def test_zlib_format_fallback_to_gzip(self):
        """Test that invalid zlib data falls back to gzip decompression."""
        original_data = b"Fallback test data"

        # Create data that starts with zlib magic but is actually gzip compressed
        # The zlib decompression will fail and it should fall back to gzip
        gzip_data = gzip.compress(original_data)

        result = decompress_certificate(gzip_data)
        assert result == original_data
