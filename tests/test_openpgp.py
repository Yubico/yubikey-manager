import hashlib

import pytest

from yubikit.openpgp import (
    DEFAULT_ADMIN_PIN,
    DEFAULT_USER_PIN,
    HASH_ALGORITHM,
    PW,
    Kdf,
    KdfIterSaltedS2k,
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
