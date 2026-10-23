import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from yubikit.core import TRANSPORT, Tlv
from yubikit.core.smartcard import SW, SmartCardConnection

from yubikit.openpgp import (
    DEFAULT_ADMIN_PIN,
    DEFAULT_USER_PIN,
    HASH_ALGORITHM,
    PW,
    Kdf,
    KdfIterSaltedS2k,
    OpenPgpSession,
)


def reference_s2k(algorithm, count, salt, pin):
    data = salt + pin.encode()
    message = data
    while len(message) < count:
        message += data[: count - len(message)]
    return hashlib.new(algorithm.name.lower(), message).digest()


@pytest.mark.parametrize("algorithm", list(HASH_ALGORITHM))
@pytest.mark.parametrize("count", [0, 1, 7, 8, 9, 13, 14, 15, 16, 27, 28, 29, 1024])
@pytest.mark.parametrize("pin", ["123456", "12345678", "12345\u00e9"])
@pytest.mark.parametrize("separate_salts", [False, True])
def test_kdf_hashes_full_sequence(algorithm, count, pin, separate_salts):
    kdf = KdfIterSaltedS2k(
        algorithm,
        count,
        b"12345678",
        b"abcdefgh" if separate_salts else None,
        b"ABCDEFGH" if separate_salts else None,
        None,
        None,
    )
    parsed = Kdf.parse(bytes(kdf))
    assert isinstance(parsed, KdfIterSaltedS2k)
    kdf = parsed
    for pw in PW:
        salt = kdf.get_salt(pw) or kdf.salt_user
        assert kdf.process(pw, pin) == reference_s2k(algorithm, count, salt, pin)


@pytest.mark.parametrize("algorithm", list(HASH_ALGORITHM))
@pytest.mark.parametrize("count", [0, 8, 15, 16])
def test_kdf_initial_hashes_include_full_pins(algorithm, count):
    kdf = KdfIterSaltedS2k.create(algorithm, count)
    for pw, pin, initial in [
        (PW.USER, DEFAULT_USER_PIN, kdf.initial_hash_user),
        (PW.ADMIN, DEFAULT_ADMIN_PIN, kdf.initial_hash_admin),
    ]:
        expected = reference_s2k(algorithm, count, kdf.get_salt(pw), pin)
        assert initial == expected
        assert kdf.process(pw, pin) == expected


class SigningConnection(SmartCardConnection):
    def __init__(self, attributes):
        self.sent = []
        discretionary = (
            Tlv(0xC0, bytes(10))
            + Tlv(0xC1, attributes)
            + Tlv(0xC2, attributes)
            + Tlv(0xC3, attributes)
            + Tlv(0xC4, b"\x01\x7f\x7f\x7f\x03\x03\x03")
            + Tlv(0xC5, b"")
            + Tlv(0xC6, b"")
            + Tlv(0xCD, b"")
        )
        aid = bytes.fromhex("d2760001240103040006123456780000")
        self.app_data = Tlv(
            0x6E, Tlv(0x4F, aid) + Tlv(0x5F52, b"") + Tlv(0x73, discretionary)
        )

    @property
    def transport(self):
        return TRANSPORT.USB

    def close(self):
        pass

    def send_and_receive(self, apdu):
        self.sent.append(apdu)
        instruction = apdu[1]
        if instruction == 0xA4:
            return b"", SW.OK
        if instruction == 0xF1:
            return b"\x05\x07\x02", SW.OK
        if instruction == 0xCA:
            assert apdu[2:4] == b"\x00\x6e"
            return self.app_data, SW.OK
        if instruction in (0x2A, 0x88):
            return b"\x11" * 64, SW.OK
        pytest.fail(f"Unexpected APDU: {apdu.hex()}")


@pytest.mark.parametrize(
    "attributes",
    [
        pytest.param(bytes.fromhex("010800001100"), id="rsa"),
        pytest.param(bytes.fromhex("132a8648ce3d030107"), id="ecdsa-p256"),
    ],
)
@pytest.mark.parametrize(
    "hash_algorithm", [hashes.SHA1, hashes.SHA256, hashes.SHA384, hashes.SHA512]
)
@pytest.mark.parametrize(
    ("operation", "instruction"), [("sign", 0x2A), ("authenticate", 0x88)]
)
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_prehashed_digest_lengths_before_signing_command(
    attributes, hash_algorithm, operation, instruction, offset
):
    hash_algorithm = hash_algorithm()
    digest_length = hash_algorithm.digest_size
    connection = SigningConnection(attributes)
    with OpenPgpSession(connection) as session:
        digest = b"\x11" * (digest_length + offset)
        if offset:
            with pytest.raises(
                RuntimeError,
                match=f"Prehashed input must contain exactly {digest_length} bytes",
            ):
                getattr(session, operation)(digest, Prehashed(hash_algorithm))
            assert all(apdu[1] not in (0x2A, 0x88) for apdu in connection.sent)
        else:
            assert getattr(session, operation)(digest, Prehashed(hash_algorithm))
            assert [apdu[1] for apdu in connection.sent if apdu[1] in (0x2A, 0x88)] == [
                instruction
            ]
