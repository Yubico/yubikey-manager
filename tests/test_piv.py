import gzip
import hashlib
import zlib
from datetime import date, datetime, timezone
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from yubikit.core import BadResponseError, Tlv
from yubikit.piv import (
    ALGORITHM,
    KEY_TYPE,
    SLOT,
    TAG_LRC,
    Chuid,
    FascN,
    PivSession,
    _pad_message,
    _unpad_message,
    calculate_ml_dsa_mu,
    decompress_certificate,
    generate_ccc,
    generate_chuid,
    generate_csr,
    generate_self_signed_certificate,
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


def test_generate_chuid():
    chuid = Chuid.from_bytes(generate_chuid())
    assert chuid.fasc_n == FascN(9999, 9999, 999999, 0, 1, 0, 3, 0, 1)
    assert chuid.expiration_date == date(2030, 1, 1)
    assert chuid.asymmetric_signature == b""
    assert len(chuid.guid) == 16
    assert chuid.guid != Chuid.from_bytes(generate_chuid()).guid


def test_generate_ccc():
    ccc = Tlv.parse_dict(generate_ccc())
    assert ccc[0xF0].startswith(b"\xa0\x00\x00\x01\x16\xff\x02")
    assert len(ccc[0xF0]) == 21
    assert ccc[0xF0] != Tlv.parse_dict(generate_ccc())[0xF0]
    assert ccc[0xF1] == ccc[0xF2] == b"\x21"
    assert ccc[TAG_LRC] == b""


@pytest.mark.parametrize(
    "key_type",
    [
        KEY_TYPE.RSA2048,
        KEY_TYPE.ECCP256,
        KEY_TYPE.ECCP384,
        KEY_TYPE.ED25519,
        KEY_TYPE.MLDSA44,
        KEY_TYPE.MLDSA65,
        KEY_TYPE.MLDSA87,
    ],
)
def test_generate_certificate_and_csr(key_type):
    if key_type == KEY_TYPE.RSA2048:
        private_key = rsa.generate_private_key(65537, 2048)
    elif key_type in (KEY_TYPE.ECCP256, KEY_TYPE.ECCP384):
        private_key = ec.generate_private_key(
            ec.SECP256R1() if key_type == KEY_TYPE.ECCP256 else ec.SECP384R1()
        )
    elif key_type == KEY_TYPE.ED25519:
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        pytest.importorskip("cryptography", minversion="49")
        mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
        private_key = getattr(mldsa, f"{key_type.name}PrivateKey").generate()

    def sign(slot, algorithm, data, hash_algorithm, rsa_padding):
        assert slot == SLOT.SIGNATURE
        assert algorithm == key_type
        if isinstance(private_key, rsa.RSAPrivateKey):
            return private_key.sign(data, rsa_padding, hash_algorithm)
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(data, ec.ECDSA(hash_algorithm))
        return private_key.sign(data)

    session = Mock(spec=PivSession)
    session.sign.side_effect = sign
    public_key = private_key.public_key()
    now = datetime.now(timezone.utc)
    certificate = generate_self_signed_certificate(
        session, SLOT.SIGNATURE, public_key, "CN=alice", now, now
    )
    assert certificate.public_key() == public_key
    assert certificate.subject == x509.Name.from_rfc4514_string("CN=alice")
    certificate.verify_directly_issued_by(certificate)

    csr = generate_csr(session, SLOT.SIGNATURE, public_key, "CN=alice")
    assert csr.public_key() == public_key
    assert csr.subject == certificate.subject
    assert csr.is_signature_valid
    assert session.sign.call_count == 2


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


_RSA_KEY = rsa.generate_private_key(65537, 2048)


def _raw_private(data: bytes) -> bytes:
    numbers = _RSA_KEY.private_numbers()
    n = numbers.public_numbers.n
    result = pow(int.from_bytes(data, "big"), numbers.d, n)
    return result.to_bytes(_RSA_KEY.key_size // 8, "big")


@pytest.mark.parametrize(
    "hash_algorithm",
    [
        hashes.SHA1(),
        hashes.SHA224(),
        hashes.SHA256(),
        hashes.SHA384(),
        hashes.SHA512(),
        hashes.SHA512_256(),
        hashes.SHA3_256(),
        hashes.SHA3_512(),
    ],
)
@pytest.mark.parametrize(
    "pad",
    [
        padding.PKCS1v15(),
        padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH),
        padding.PSS(padding.MGF1(hashes.SHA1()), padding.PSS.DIGEST_LENGTH),
        padding.PSS(padding.MGF1(hashes.SHA512()), 0),
    ],
)
def test_rsa_sign_padding(hash_algorithm, pad):
    message = b"PIV signature padding"
    public_key = _RSA_KEY.public_key()

    padded = _pad_message(KEY_TYPE.RSA2048, message, hash_algorithm, pad)
    public_key.verify(_raw_private(padded), message, pad, hash_algorithm)

    h = hashes.Hash(hash_algorithm)
    h.update(message)
    prehashed = Prehashed(hash_algorithm)
    padded = _pad_message(KEY_TYPE.RSA2048, h.finalize(), prehashed, pad)
    public_key.verify(_raw_private(padded), message, pad, hash_algorithm)


def test_rsa_sign_padding_errors():
    with pytest.raises(ValueError):
        _pad_message(
            KEY_TYPE.RSA2048,
            b"\0" * 31,
            Prehashed(hashes.SHA256()),
            padding.PKCS1v15(),
        )
    with pytest.raises(ValueError):
        _pad_message(
            KEY_TYPE.RSA2048,
            b"message",
            hashes.SHA256(),
            padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.AUTO),
        )
    with pytest.raises(ValueError):
        _pad_message(
            KEY_TYPE.RSA1024,
            b"message",
            hashes.SHA512(),
            padding.PSS(padding.MGF1(hashes.SHA512()), 100),
        )


@pytest.mark.parametrize(
    "pad",
    [
        padding.PKCS1v15(),
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None),
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None),
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA384(), b"label"),
    ],
)
def test_rsa_decrypt_unpadding(pad):
    message = b"PIV decryption padding"
    ciphertext = _RSA_KEY.public_key().encrypt(message, pad)
    assert _unpad_message(_raw_private(ciphertext), pad) == message

    with pytest.raises(ValueError):
        _unpad_message(b"\0" * 256, pad)


def test_ec_sign_hash_truncation():
    message = b"message"
    h = hashes.Hash(hashes.SHA384())
    h.update(message)
    digest = h.finalize()
    assert _pad_message(KEY_TYPE.ECCP256, message, hashes.SHA384(), None) == digest[:32]
    assert (
        _pad_message(KEY_TYPE.ECCP256, digest[:32], Prehashed(hashes.SHA256()), None)
        == digest[:32]
    )
    assert _pad_message(KEY_TYPE.ECCP384, message, hashes.SHA384(), None) == digest
    h = hashes.Hash(hashes.SHA256())
    h.update(message)
    assert (
        _pad_message(KEY_TYPE.ECCP384, message, hashes.SHA256(), None) == h.finalize()
    )


@pytest.mark.parametrize(
    "key_type, algorithm",
    [
        (KEY_TYPE.MLDSA44, ALGORITHM.MLDSA),
        (KEY_TYPE.MLDSA65, ALGORITHM.MLDSA),
        (KEY_TYPE.MLDSA87, ALGORITHM.MLDSA),
        (KEY_TYPE.MLKEM512, ALGORITHM.MLKEM),
        (KEY_TYPE.MLKEM768, ALGORITHM.MLKEM),
        (KEY_TYPE.MLKEM1024, ALGORITHM.MLKEM),
    ],
)
def test_pqc_key_types(key_type, algorithm):
    assert key_type.algorithm == algorithm
    with pytest.raises(ValueError):
        key_type.bit_len


def test_pqc_from_public_key():
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    mlkem = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mlkem")
    for cls, key_type in [
        (mldsa.MLDSA44PrivateKey, KEY_TYPE.MLDSA44),
        (mldsa.MLDSA65PrivateKey, KEY_TYPE.MLDSA65),
        (mldsa.MLDSA87PrivateKey, KEY_TYPE.MLDSA87),
        (mlkem.MLKEM768PrivateKey, KEY_TYPE.MLKEM768),
        (mlkem.MLKEM1024PrivateKey, KEY_TYPE.MLKEM1024),
    ]:
        assert KEY_TYPE.from_public_key(cls.generate().public_key()) == key_type


def test_ml_dsa_sign_message_passthrough():
    message = b"message"
    assert _pad_message(KEY_TYPE.MLDSA65, message, None, None) == message
    with pytest.raises(ValueError):
        _pad_message(KEY_TYPE.MLDSA65, message, Prehashed(hashes.SHA256()), None)


def test_calculate_ml_dsa_mu():
    public_key = bytes(range(256)) * 5 + bytes(32)  # ML-DSA-44 sized
    message = b"message"
    for context in (b"", b"context"):
        tr = hashlib.shake_256(public_key).digest(64)
        expected = hashlib.shake_256(
            tr + bytes([0, len(context)]) + context + message
        ).digest(64)
        assert calculate_ml_dsa_mu(public_key, message, context) == expected
    with pytest.raises(ValueError):
        calculate_ml_dsa_mu(public_key, message, bytes(256))


def test_calculate_ml_dsa_mu_matches_cryptography():
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    if not hasattr(mldsa, "MLDSAMuHasher"):
        pytest.skip("Requires cryptography >= 50")
    public_key = mldsa.MLDSA65PrivateKey.generate().public_key()
    message = b"message"
    hasher = mldsa.MLDSAMuHasher(public_key, b"context")
    hasher.update(message)
    assert calculate_ml_dsa_mu(public_key, message, b"context") == hasher.finalize()
