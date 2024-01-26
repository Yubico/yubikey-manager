import pytest

from yubikit.core.smartcard import ApduError
from yubikit.management import CAPABILITY
from yubikit.hsmauth import (
    HsmAuthSession,
    Credential,
    INITIAL_RETRY_COUNTER,
    InvalidPinError,
)

from . import condition

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import os

DEFAULT_MANAGEMENT_KEY = bytes.fromhex("00000000000000000000000000000000")
NON_DEFAULT_MANAGEMENT_KEY = bytes.fromhex("11111111111111111111111111111111")


@pytest.fixture
@condition.capability(CAPABILITY.HSMAUTH)
@condition.min_version(5, 4, 3)
def session(ccid_connection):
    hsmauth = HsmAuthSession(ccid_connection)
    hsmauth.reset()
    yield hsmauth


def import_key_derived(
    session,
    management_key,
    credential_password="123456",
    derivation_password="password",
) -> Credential:
    credential = session.put_credential_derived(
        management_key,
        "Test PUT credential symmetric (derived)",
        derivation_password,
        credential_password,
    )

    return credential


def import_key_symmetric(
    session, management_key, key_enc, key_mac, credential_password="123456"
) -> Credential:
    credential = session.put_credential_symmetric(
        management_key,
        "Test PUT credential symmetric",
        key_enc,
        key_mac,
        credential_password,
    )

    return credential


def import_key_asymmetric(
    session, management_key, private_key, credential_password="123456"
) -> Credential:
    credential = session.put_credential_asymmetric(
        management_key,
        "Test PUT credential asymmetric",
        private_key,
        credential_password,
    )

    return credential


def generate_key_asymmetric(
    session, management_key, credential_password="123456"
) -> Credential:
    credential = session.generate_credential_asymmetric(
        management_key,
        "Test GENERATE credential asymmetric",
        credential_password,
    )

    return credential


class TestCredentialManagement:
    def check_credential_in_list(self, session, credential: Credential):
        credentials = session.list_credentials()

        assert credential in credentials
        credential_retrieved = next(cred for cred in credentials if cred == credential)
        assert credential_retrieved.label == credential.label
        assert credential_retrieved.touch_required == credential.touch_required
        assert credential_retrieved.algorithm == credential.algorithm
        assert credential_retrieved.counter == INITIAL_RETRY_COUNTER

    def verify_credential_password(
        self, session, credential_password: str, credential: Credential
    ):
        context = b"g\xfc\xf1\xfe\xb5\xf1\xd8\x83\xedv=\xbfI0\x90\xbb"

        # Try to calculate session keys using credential password
        session.calculate_session_keys_symmetric(
            label=credential.label,
            context=context,
            credential_password=credential_password,
        )

    def test_import_credential_symmetric_wrong_management_key(self, session):
        with pytest.raises(InvalidPinError):
            import_key_derived(session, NON_DEFAULT_MANAGEMENT_KEY)

    def test_import_credential_symmetric_wrong_key_length(self, session):
        with pytest.raises(ValueError):
            import_key_symmetric(
                session, DEFAULT_MANAGEMENT_KEY, os.urandom(24), os.urandom(24)
            )

    def test_import_credential_symmetric_exists(self, session):
        import_key_derived(session, DEFAULT_MANAGEMENT_KEY)
        with pytest.raises(ApduError):
            import_key_derived(session, DEFAULT_MANAGEMENT_KEY)

    def test_import_credential_symmetric_works(self, session):
        credential = import_key_derived(session, DEFAULT_MANAGEMENT_KEY, "1234")

        self.verify_credential_password(session, "1234", credential)
        self.check_credential_in_list(session, credential)

        session.delete_credential(DEFAULT_MANAGEMENT_KEY, credential.label)

    @condition.min_version(5, 6)
    def test_import_credential_asymmetric_unsupported_key(self, session):
        private_key = ec.generate_private_key(
            ec.SECP224R1(), backend=default_backend()
        )  # curve secp224r1 is not supported

        with pytest.raises(ValueError):
            import_key_asymmetric(session, DEFAULT_MANAGEMENT_KEY, private_key)

    @condition.min_version(5, 6)
    def test_import_credential_asymmetric_works(self, session):
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        credential = import_key_asymmetric(session, DEFAULT_MANAGEMENT_KEY, private_key)

        public_key = private_key.public_key()
        assert public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ) == session.get_public_key(credential.label).public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        )

        self.check_credential_in_list(session, credential)
        session.delete_credential(DEFAULT_MANAGEMENT_KEY, credential.label)

    @condition.min_version(5, 6)
    def test_generate_credential_asymmetric_works(self, session):
        credential = generate_key_asymmetric(session, DEFAULT_MANAGEMENT_KEY)

        self.check_credential_in_list(session, credential)

        public_key = session.get_public_key(credential.label)

        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        assert isinstance(public_key.curve, ec.SECP256R1)

        session.delete_credential(DEFAULT_MANAGEMENT_KEY, credential.label)

    @condition.min_version(5, 6)
    def test_export_public_key_symmetric_credential(self, session):
        credential = import_key_derived(session, DEFAULT_MANAGEMENT_KEY)

        with pytest.raises(ApduError):
            session.get_public_key(credential.label)

        session.delete_credential(DEFAULT_MANAGEMENT_KEY, credential.label)

    def test_delete_credential_wrong_management_key(self, session):
        credential = import_key_derived(session, DEFAULT_MANAGEMENT_KEY)

        with pytest.raises(InvalidPinError):
            session.delete_credential(NON_DEFAULT_MANAGEMENT_KEY, credential.label)

    def test_delete_credential_non_existing(self, session):
        with pytest.raises(ApduError):
            session.delete_credential(DEFAULT_MANAGEMENT_KEY, "Default key")

    def test_delete_credential_works(self, session):
        credential = import_key_derived(session, DEFAULT_MANAGEMENT_KEY)

        session.delete_credential(DEFAULT_MANAGEMENT_KEY, credential.label)
        credentials = session.list_credentials()
        assert len(credentials) == 0


class TestAccess:
    def test_change_management_key(self, session):
        session.put_management_key(DEFAULT_MANAGEMENT_KEY, NON_DEFAULT_MANAGEMENT_KEY)

        # Can't import key with old management key
        with pytest.raises(InvalidPinError):
            import_key_derived(session, DEFAULT_MANAGEMENT_KEY)

        session.put_management_key(NON_DEFAULT_MANAGEMENT_KEY, DEFAULT_MANAGEMENT_KEY)

    def test_management_key_retries(self, session):
        session.put_management_key(DEFAULT_MANAGEMENT_KEY, DEFAULT_MANAGEMENT_KEY)
        initial_retries = session.get_management_key_retries()
        assert initial_retries == 8

        with pytest.raises(InvalidPinError):
            import_key_derived(session, NON_DEFAULT_MANAGEMENT_KEY)

        post_retries = session.get_management_key_retries()
        assert post_retries == 7


class TestSessionKeys:
    def test_calculate_session_keys_symmetric(self, session):
        credential_password = "1234"
        credential = import_key_derived(
            session,
            DEFAULT_MANAGEMENT_KEY,
            credential_password=credential_password,
            derivation_password="pwd",
        )

        # Example context and session keys
        context = b"g\xfc\xf1\xfe\xb5\xf1\xd8\x83\xedv=\xbfI0\x90\xbb"
        key_senc = b"\xb0o\x1a\xc9\x87\x91.\xbe\xdc\x1b\xf0\xe0*k]\x85"
        key_smac = b"\xea\xd6\xc3\xa5\x96\xea\x86u\xbf1\xd3I\xab\xb5,t"
        key_srmac = b"\xc2\xc6\x1e\x96\xab,X\xe9\x83z\xd0\xe7\xd0n\xe9\x0c"

        session_keys = session.calculate_session_keys_symmetric(
            label=credential.label,
            context=context,
            credential_password=credential_password,
        )

        assert key_senc == session_keys.key_senc
        assert key_smac == session_keys.key_smac
        assert key_srmac == session_keys.key_srmac


class TestHostChallenge:
    @condition.min_version(5, 6)
    def test_get_challenge_symmetric(self, session):
        credential = import_key_derived(session, DEFAULT_MANAGEMENT_KEY)

        challenge1 = session.get_challenge(credential.label)
        challenge2 = session.get_challenge(credential.label)
        assert len(challenge1) == 8
        assert len(challenge2) == 8
        assert challenge1 != challenge2

        session.delete_credential(DEFAULT_MANAGEMENT_KEY, credential.label)

    @condition.min_version(5, 6)
    def test_get_challenge_asymmetric(self, session):
        credential = generate_key_asymmetric(session, DEFAULT_MANAGEMENT_KEY)

        challenge1 = session.get_challenge(credential.label)
        challenge2 = session.get_challenge(credential.label)

        assert len(challenge1) == 65
        assert len(challenge2) == 65
        assert challenge1 != challenge2

        session.delete_credential(DEFAULT_MANAGEMENT_KEY, credential.label)
