import pytest

from yubikit.core import AID
from yubikit.core.smartcard import ApduError, SW
from yubikit.management import CAPABILITY
from yubikit.oath import (
    OathSession,
    CredentialData,
    HASH_ALGORITHM,
    OATH_TYPE,
)
from ykman.device import is_fips_version
from . import condition


KEY = bytes.fromhex("01020304050607080102030405060708")


@pytest.fixture
@condition.capability(CAPABILITY.OATH)
def session(ccid_connection):
    oath = OathSession(ccid_connection)
    oath.reset()
    yield oath


CRED_DATA = CredentialData("name", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, b"secret")


class TestFunctions:
    @condition.min_version(5, 3)
    def test_rename(self, session):
        cred = session.put_credential(CRED_DATA)
        new_id = session.rename_credential(cred.id, "newname", "newissuer")
        with pytest.raises(ApduError):
            session.calculate(cred.id, b"challenge")
        session.calculate(new_id, b"challenge")

    @condition.min_version(5, 3)
    def test_rename_to_existing(self, session):
        cred = session.put_credential(CRED_DATA)
        new_id = session.rename_credential(cred.id, "newname", "newissuer")
        with pytest.raises(ApduError):
            session.rename_credential(new_id, "newname", "newissuer")


class TestLockPreventsAccess:
    @pytest.fixture(autouse=True)
    def set_lock(self, session):
        assert not session.locked
        session.put_credential(CRED_DATA)
        session.set_key(KEY)

        # Force re-select to lock
        session.protocol.connection.connection.disconnect()
        session.protocol.connection.connection.connect()
        session.protocol.select(AID.OATH)

    def test_list(self, session):
        with pytest.raises(ApduError) as ctx:
            session.list_credentials()
        assert ctx.value.sw == SW.SECURITY_CONDITION_NOT_SATISFIED

    def test_calculate(self, session):
        with pytest.raises(ApduError) as ctx:
            session.calculate(CRED_DATA.get_id(), b"challenge")
        assert ctx.value.sw == SW.SECURITY_CONDITION_NOT_SATISFIED

    def test_calculate_all(self, session):
        with pytest.raises(ApduError) as ctx:
            session.calculate_all()
        assert ctx.value.sw == SW.SECURITY_CONDITION_NOT_SATISFIED

    def test_delete(self, session):
        with pytest.raises(ApduError) as ctx:
            session.delete_credential(CRED_DATA.get_id())
        assert ctx.value.sw == SW.SECURITY_CONDITION_NOT_SATISFIED

    @condition.min_version(5, 3)
    def test_rename(self, session):
        with pytest.raises(ApduError) as ctx:
            session.rename_credential(CRED_DATA.get_id(), "renamed")
        assert ctx.value.sw == SW.SECURITY_CONDITION_NOT_SATISFIED


HMAC_VECTORS = {
    b"\x0B"
    * 20: {
        b"Hi There": {
            HASH_ALGORITHM.SHA256: bytes.fromhex(
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            ),
            HASH_ALGORITHM.SHA512: bytes.fromhex(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ),
        }
    },
    b"Jefe": {
        b"what do ya want for nothing?": {
            HASH_ALGORITHM.SHA256: bytes.fromhex(
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            ),
            HASH_ALGORITHM.SHA512: bytes.fromhex(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ),
        }
    },
    b"\xAA"
    * 20: {
        b"\xDD"
        * 50: {
            HASH_ALGORITHM.SHA256: bytes.fromhex(
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
            ),
            HASH_ALGORITHM.SHA512: bytes.fromhex(
                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
            ),
        }
    },
    bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819"): {
        b"\xCD"
        * 50: {
            HASH_ALGORITHM.SHA256: bytes.fromhex(
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
            ),
            HASH_ALGORITHM.SHA512: bytes.fromhex(
                "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
            ),
        }
    },
}


HMAC_PARAMS = [
    (key, timestamp, algo, HMAC_VECTORS[key][timestamp][algo])
    for key in HMAC_VECTORS
    for timestamp in HMAC_VECTORS[key]
    for algo in HMAC_VECTORS[key][timestamp]
]


def _ids_hmac(params):
    key, challenge, hash_algorithm, expected = params
    key_s = key.hex() if len(key) < 6 else key[:6].hex() + "..."
    challenge_s = challenge.hex() if len(challenge) < 6 else challenge[:6].hex() + "..."
    return f"{hash_algorithm.name}-{key_s}-{challenge_s}"


class TestHmacVectors:
    @pytest.mark.parametrize("params", HMAC_PARAMS, ids=_ids_hmac)
    def test_vector(self, session, params):
        key, challenge, hash_algorithm, expected = params
        if hash_algorithm == HASH_ALGORITHM.SHA512:
            if session.version < (4, 3, 1) or is_fips_version(session.version):
                pytest.skip("SHA512 requires (non-FIPS) YubiKey 4.3.1 or later")
        cred = session.put_credential(
            CredentialData("test", OATH_TYPE.TOTP, hash_algorithm, key)
        )
        value = session.calculate(cred.id, challenge)
        assert value == expected


TOTP_VECTOR_KEYS = {
    HASH_ALGORITHM.SHA1: b"12345678901234567890",
    HASH_ALGORITHM.SHA256: b"12345678901234567890123456789012",
    HASH_ALGORITHM.SHA512: b"12345678901234567890123456789012"
    b"34567890123456789012345678901234",
}
TOTP_VECTORS = {
    59: {
        HASH_ALGORITHM.SHA1: "94287082",
        HASH_ALGORITHM.SHA256: "46119246",
        HASH_ALGORITHM.SHA512: "90693936",
    },
    1111111109: {
        HASH_ALGORITHM.SHA1: "07081804",
        HASH_ALGORITHM.SHA256: "68084774",
        HASH_ALGORITHM.SHA512: "25091201",
    },
}


TOTP_PARAMS = [
    (timestamp, algo, TOTP_VECTORS[timestamp][algo], TOTP_VECTOR_KEYS[algo])
    for timestamp in TOTP_VECTORS
    for algo in TOTP_VECTORS[timestamp]
]


class TestTotpVectors:
    @pytest.mark.parametrize("digits", [6, 8])
    @pytest.mark.parametrize(
        "params", TOTP_PARAMS, ids=lambda x: "{1.name}-{0}".format(*x)
    )
    def test_vector(self, session, params, digits):
        timestamp, hash_algorithm, value, key = params
        if hash_algorithm == HASH_ALGORITHM.SHA512:
            if session.version < (4, 3, 1) or is_fips_version(session.version):
                pytest.skip("SHA512 requires (non-FIPS) YubiKey 4.3.1 or later")

        cred = session.put_credential(
            CredentialData("test", OATH_TYPE.TOTP, hash_algorithm, key, digits)
        )
        code = session.calculate_code(cred, timestamp)
        assert len(code.value) == digits
        assert value.endswith(code.value)


HOTP_VECTORS = {
    b"12345678901234567890": [
        "84755224",
        "94287082",
        "37359152",
        "26969429",
        "40338314",
        "68254676",
        "18287922",
        "82162583",
        "73399871",
        "45520489",
    ]
}


class TestHotpVectors:
    @pytest.mark.parametrize("digits", [6, 8])
    @pytest.mark.parametrize(
        "params", HOTP_VECTORS.items(), ids=lambda x: "{0}".format(*x)
    )
    def test_vector(self, session, params, digits):
        key, values = params

        cred = session.put_credential(
            CredentialData("test", OATH_TYPE.HOTP, HASH_ALGORITHM.SHA1, key, digits)
        )
        for expected in values:
            code = session.calculate_code(cred)
            assert len(code.value) == digits
            assert expected.endswith(code.value)
