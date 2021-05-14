import datetime
import random
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

from yubikit.core import AID, NotSupportedError
from yubikit.core.smartcard import ApduError
from yubikit.management import CAPABILITY
from yubikit.piv import (
    PivSession,
    ALGORITHM,
    KEY_TYPE,
    PIN_POLICY,
    TOUCH_POLICY,
    SLOT,
    MANAGEMENT_KEY_TYPE,
    InvalidPinError,
)
from ykman.piv import (
    check_key,
    get_pivman_data,
    get_pivman_protected_data,
    generate_self_signed_certificate,
    generate_csr,
    pivman_set_mgm_key,
)
from ykman.util import parse_certificates, parse_private_key
from ykman.device import is_fips_version
from ..util import open_file
from . import condition


DEFAULT_PIN = "123456"
NON_DEFAULT_PIN = "654321"
DEFAULT_PUK = "12345678"
NON_DEFAULT_PUK = "87654321"
DEFAULT_MANAGEMENT_KEY = bytes.fromhex(
    "010203040506070801020304050607080102030405060708"
)
NON_DEFAULT_MANAGEMENT_KEY = bytes.fromhex(
    "010103040506070801020304050607080102030405060708"
)

NOW = datetime.datetime.now()


def get_test_cert():
    with open_file("rsa_2048_cert.pem") as f:
        return parse_certificates(f.read(), None)[0]


def get_test_key():
    with open_file("rsa_2048_key.pem") as f:
        return parse_private_key(f.read(), None)


@pytest.fixture
@condition.capability(CAPABILITY.PIV)
def session(ccid_connection):
    piv = PivSession(ccid_connection)
    piv.reset()
    yield piv
    reset_state(piv)


def not_roca(version):
    return not ((4, 2, 0) <= version < (4, 3, 5))


def reset_state(session):
    session.protocol.connection.connection.disconnect()
    session.protocol.connection.connection.connect()
    session.protocol.select(AID.PIV)


def assert_mgm_key_is(session, key):
    session.authenticate(MANAGEMENT_KEY_TYPE.TDES, key)


def assert_mgm_key_is_not(session, key):
    with pytest.raises(ApduError):
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, key)


def generate_key(
    session,
    slot=SLOT.AUTHENTICATION,
    alg=KEY_TYPE.ECCP256,
    pin_policy=PIN_POLICY.DEFAULT,
):
    session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
    key = session.generate_key(slot, alg, pin_policy=pin_policy)
    reset_state(session)
    return key


def import_key(
    session,
    slot=SLOT.AUTHENTICATION,
    key_type=KEY_TYPE.ECCP256,
    pin_policy=PIN_POLICY.DEFAULT,
):

    if key_type.algorithm == ALGORITHM.RSA:
        private_key = rsa.generate_private_key(
            65537, key_type.bit_len, default_backend()
        )
    elif key_type == KEY_TYPE.ECCP256:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif key_type == KEY_TYPE.ECCP384:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
    session.put_key(slot, private_key, pin_policy)
    reset_state(session)
    return private_key.public_key()


def verify_cert_signature(cert, public_key=None):
    if not public_key:
        public_key = cert.public_key
    args = [cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm]
    if KEY_TYPE.from_public_key(public_key).algorithm == ALGORITHM.RSA:
        args.insert(2, padding.PKCS1v15())
    else:
        args[2] = ec.ECDSA(args[2])
    public_key.verify(*args)


class TestCertificateSignatures:
    @pytest.mark.parametrize("key_type", list(KEY_TYPE))
    @pytest.mark.parametrize(
        "hash_algorithm", (hashes.SHA1, hashes.SHA256, hashes.SHA384, hashes.SHA512)
    )
    def test_generate_self_signed_certificate(self, session, key_type, hash_algorithm):
        if key_type == KEY_TYPE.ECCP384 and session.version < (4, 0, 0):
            pytest.skip("ECCP384 requires YubiKey 4 or later")
        if key_type == KEY_TYPE.RSA1024 and is_fips_version(session.version):
            pytest.skip("RSA1024 not available on YubiKey FIPS")

        slot = SLOT.SIGNATURE
        public_key = import_key(session, slot, key_type)
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.verify_pin(DEFAULT_PIN)
        cert = generate_self_signed_certificate(
            session, slot, public_key, "CN=alice", NOW, NOW, hash_algorithm
        )

        assert cert.public_key().public_numbers() == public_key.public_numbers()
        verify_cert_signature(cert, public_key)


class TestKeyManagement:
    def test_delete_certificate_requires_authentication(self, session):
        generate_key(session, SLOT.AUTHENTICATION)

        with pytest.raises(ApduError):
            session.delete_certificate(SLOT.AUTHENTICATION)

        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.delete_certificate(SLOT.AUTHENTICATION)

    def test_generate_csr_works(self, session):
        public_key = generate_key(session, SLOT.AUTHENTICATION)

        session.verify_pin(DEFAULT_PIN)
        csr = generate_csr(session, SLOT.AUTHENTICATION, public_key, "CN=alice")

        assert csr.public_key().public_numbers() == public_key.public_numbers()
        assert (
            csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            == "alice"
        )

    def test_generate_self_signed_certificate_requires_pin(self, session):
        session.verify_pin(DEFAULT_PIN)
        public_key = generate_key(session, SLOT.AUTHENTICATION)

        with pytest.raises(ApduError):
            generate_self_signed_certificate(
                session, SLOT.AUTHENTICATION, public_key, "CN=alice", NOW, NOW
            )

        session.verify_pin(DEFAULT_PIN)
        generate_self_signed_certificate(
            session, SLOT.AUTHENTICATION, public_key, "CN=alice", NOW, NOW
        )

    @pytest.mark.parametrize("slot", (SLOT.SIGNATURE, SLOT.AUTHENTICATION))
    def test_generate_self_signed_certificate(self, session, slot):
        public_key = generate_key(session, slot)
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.verify_pin(DEFAULT_PIN)
        cert = generate_self_signed_certificate(
            session, slot, public_key, "CN=alice", NOW, NOW
        )

        assert cert.public_key().public_numbers() == public_key.public_numbers()
        assert (
            cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            == "alice"
        )

    def test_generate_key_requires_authentication(self, session):
        with pytest.raises(ApduError):
            session.generate_key(
                SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, touch_policy=TOUCH_POLICY.DEFAULT
            )

        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)

    def test_put_certificate_requires_authentication(self, session):
        cert = get_test_cert()
        with pytest.raises(ApduError):
            session.put_certificate(SLOT.AUTHENTICATION, cert)

        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.put_certificate(SLOT.AUTHENTICATION, cert)

    def _test_put_key_pairing(self, session, alg1, alg2):
        # Set up a key in the slot and create a certificate for it
        public_key = generate_key(session, SLOT.AUTHENTICATION, alg=alg1)
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.verify_pin(DEFAULT_PIN)
        cert = generate_self_signed_certificate(
            session, SLOT.AUTHENTICATION, public_key, "CN=test", NOW, NOW
        )
        session.put_certificate(SLOT.AUTHENTICATION, cert)
        assert check_key(session, SLOT.AUTHENTICATION, cert.public_key())

        cert2 = session.get_certificate(SLOT.AUTHENTICATION)
        assert cert == cert2

        session.delete_certificate(SLOT.AUTHENTICATION)

        # Overwrite the key with one of the same type
        generate_key(session, SLOT.AUTHENTICATION, alg=alg1)
        session.verify_pin(DEFAULT_PIN)
        assert not check_key(session, SLOT.AUTHENTICATION, cert.public_key())

        # Overwrite the key with one of a different type
        generate_key(session, SLOT.AUTHENTICATION, alg=alg2)
        session.verify_pin(DEFAULT_PIN)
        assert not check_key(session, SLOT.AUTHENTICATION, cert.public_key())

    @condition.check(not_roca)
    @condition.fips(False)
    def test_put_certificate_verifies_key_pairing_rsa1024(self, session):
        self._test_put_key_pairing(session, KEY_TYPE.RSA1024, KEY_TYPE.ECCP256)

    @condition.check(not_roca)
    def test_put_certificate_verifies_key_pairing_rsa2048(self, session):
        self._test_put_key_pairing(session, KEY_TYPE.RSA2048, KEY_TYPE.ECCP256)

    @condition.check(not_roca)
    def test_put_certificate_verifies_key_pairing_eccp256_a(self, session):
        self._test_put_key_pairing(session, KEY_TYPE.ECCP256, KEY_TYPE.RSA2048)

    @condition.min_version(4)
    def test_put_certificate_verifies_key_pairing_eccp256_b(self, session):
        self._test_put_key_pairing(session, KEY_TYPE.ECCP256, KEY_TYPE.ECCP384)

    @condition.min_version(4)
    def test_put_certificate_verifies_key_pairing_eccp384(self, session):
        self._test_put_key_pairing(session, KEY_TYPE.ECCP384, KEY_TYPE.ECCP256)

    def test_put_key_requires_authentication(self, session):
        private_key = get_test_key()
        with pytest.raises(ApduError):
            session.put_key(SLOT.AUTHENTICATION, private_key)

        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.put_key(SLOT.AUTHENTICATION, private_key)

    def test_get_certificate_does_not_require_authentication(self, session):
        cert = get_test_cert()
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.put_certificate(SLOT.AUTHENTICATION, cert)
        reset_state(session)

        assert session.get_certificate(SLOT.AUTHENTICATION)


class TestManagementKeyReadOnly:
    """
    Tests after which the management key is always the default management
    key. Placing compatible tests here reduces the amount of slow reset
    calls needed.
    """

    def test_authenticate_twice_does_not_throw(self, session):
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)

    def test_reset_resets_has_stored_key_flag(self, session):
        pivman = get_pivman_data(session)
        assert not pivman.has_stored_key

        session.verify_pin(DEFAULT_PIN)
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        pivman_set_mgm_key(
            session,
            NON_DEFAULT_MANAGEMENT_KEY,
            MANAGEMENT_KEY_TYPE.TDES,
            store_on_device=True,
        )

        pivman = get_pivman_data(session)
        assert pivman.has_stored_key

        reset_state(session)
        session.reset()

        pivman = get_pivman_data(session)
        assert not pivman.has_stored_key

    # Should this really fail?
    def disabled_test_reset_while_verified_throws_nice_ValueError(self, session):
        session.verify_pin(DEFAULT_PIN)
        with pytest.raises(ValueError) as cm:
            session.reset()
        assert "Cannot read remaining tries from status word: 9000" in str(cm.exception)

    def test_set_mgm_key_does_not_change_key_if_not_authenticated(self, session):
        with pytest.raises(ApduError):
            session.set_management_key(
                MANAGEMENT_KEY_TYPE.TDES, NON_DEFAULT_MANAGEMENT_KEY
            )
        assert_mgm_key_is(session, DEFAULT_MANAGEMENT_KEY)

    @condition.min_version(3, 5)
    def test_set_stored_mgm_key_does_not_destroy_key_if_pin_not_verified(self, session):
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        with pytest.raises(ApduError):
            pivman_set_mgm_key(
                session,
                NON_DEFAULT_MANAGEMENT_KEY,
                MANAGEMENT_KEY_TYPE.TDES,
                store_on_device=True,
            )

        assert_mgm_key_is(session, DEFAULT_MANAGEMENT_KEY)


class TestManagementKeyReadWrite:
    """
    Tests after which the management key may not be the default management
    key.
    """

    def test_set_mgm_key_changes_mgm_key(self, session):
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.set_management_key(MANAGEMENT_KEY_TYPE.TDES, NON_DEFAULT_MANAGEMENT_KEY)

        assert_mgm_key_is_not(session, DEFAULT_MANAGEMENT_KEY)
        assert_mgm_key_is(session, NON_DEFAULT_MANAGEMENT_KEY)

    def test_set_stored_mgm_key_succeeds_if_pin_is_verified(self, session):
        session.verify_pin(DEFAULT_PIN)
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        pivman_set_mgm_key(
            session,
            NON_DEFAULT_MANAGEMENT_KEY,
            MANAGEMENT_KEY_TYPE.TDES,
            store_on_device=True,
        )

        assert_mgm_key_is_not(session, DEFAULT_MANAGEMENT_KEY)
        assert_mgm_key_is(session, NON_DEFAULT_MANAGEMENT_KEY)

        pivman_prot = get_pivman_protected_data(session)
        assert pivman_prot.key == NON_DEFAULT_MANAGEMENT_KEY

        pivman_prot = get_pivman_protected_data(session)
        assert_mgm_key_is(session, pivman_prot.key)


def sign(session, slot, key_type, message):
    return session.sign(slot, key_type, message, hashes.SHA256(), padding.PKCS1v15())


class TestOperations:
    @condition.min_version(4)
    def test_sign_with_pin_policy_always_requires_pin_every_time(self, session):
        generate_key(session, pin_policy=PIN_POLICY.ALWAYS)

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(DEFAULT_PIN)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(DEFAULT_PIN)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

    @condition.fips(False)
    @condition.min_version(4)
    def test_sign_with_pin_policy_never_does_not_require_pin(self, session):
        generate_key(session, pin_policy=PIN_POLICY.NEVER)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

    @condition.fips(True)
    def test_pin_policy_never_blocked_on_fips(self, session):
        with pytest.raises(NotSupportedError):
            generate_key(session, pin_policy=PIN_POLICY.NEVER)

    @condition.min_version(4)
    def test_sign_with_pin_policy_once_requires_pin_once_per_session(self, session):
        generate_key(session, pin_policy=PIN_POLICY.ONCE)

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(DEFAULT_PIN)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        reset_state(session)

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(DEFAULT_PIN)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

    def test_signature_can_be_verified_by_public_key(self, session):
        public_key = generate_key(session)

        signed_data = bytes(random.randint(0, 255) for i in range(32))

        session.verify_pin(DEFAULT_PIN)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, signed_data)
        assert sig

        public_key.verify(sig, signed_data, ec.ECDSA(hashes.SHA256()))


def block_pin(session):
    while session.get_pin_attempts() > 0:
        try:
            session.verify_pin(NON_DEFAULT_PIN)
        except Exception:
            pass


class TestUnblockPin:
    def test_unblock_pin_requires_no_previous_authentication(self, session):
        session.unblock_pin(DEFAULT_PUK, NON_DEFAULT_PIN)

    def test_unblock_pin_with_wrong_puk_throws_InvalidPinError(self, session):
        with pytest.raises(InvalidPinError):
            session.unblock_pin(NON_DEFAULT_PUK, NON_DEFAULT_PIN)

    def test_unblock_pin_resets_pin_and_retries(self, session):
        session.reset()
        reset_state(session)

        block_pin(session)

        with pytest.raises(InvalidPinError):
            session.verify_pin(DEFAULT_PIN)

        session.unblock_pin(DEFAULT_PUK, NON_DEFAULT_PIN)

        assert session.get_pin_attempts() == 3
        session.verify_pin(NON_DEFAULT_PIN)

    def test_set_pin_retries_requires_pin_and_mgm_key(self, session):
        # Fails with no authentication
        with pytest.raises(ApduError):
            session.set_pin_attempts(4, 4)

        # Fails with only PIN
        session.verify_pin(DEFAULT_PIN)
        with pytest.raises(ApduError):
            session.set_pin_attempts(4, 4)

        reset_state(session)

        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        # Fails with only management key (requirement added in 0.1.3)
        if session.version >= (0, 1, 3):
            with pytest.raises(ApduError):
                session.set_pin_attempts(4, 4)

        # Succeeds with both PIN and management key
        session.verify_pin(DEFAULT_PIN)
        session.set_pin_attempts(4, 4)

    def test_set_pin_retries_sets_pin_and_puk_tries(self, session):
        pin_tries = 9
        puk_tries = 7

        session.verify_pin(DEFAULT_PIN)
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.set_pin_attempts(pin_tries, puk_tries)

        reset_state(session)

        assert session.get_pin_attempts() == pin_tries
        with pytest.raises(InvalidPinError) as ctx:
            session.change_puk(NON_DEFAULT_PUK, DEFAULT_PUK)
        assert ctx.value.attempts_remaining == puk_tries - 1


class TestMetadata:
    @pytest.fixture(autouse=True)
    @condition.min_version(5, 3)
    def preconditions(self):
        pass

    def test_pin_metadata(self, session):
        data = session.get_pin_metadata()
        assert data.default_value is True
        assert data.total_attempts == 3
        assert data.attempts_remaining == 3

    def test_management_key_metadata(self, session):
        data = session.get_management_key_metadata()
        assert data.key_type == MANAGEMENT_KEY_TYPE.TDES
        assert data.default_value is True
        assert data.touch_policy is TOUCH_POLICY.NEVER

        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.set_management_key(
            MANAGEMENT_KEY_TYPE.AES192, NON_DEFAULT_MANAGEMENT_KEY
        )
        data = session.get_management_key_metadata()
        assert data.key_type == MANAGEMENT_KEY_TYPE.AES192
        assert data.default_value is False
        assert data.touch_policy is TOUCH_POLICY.NEVER

        session.set_management_key(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        data = session.get_management_key_metadata()
        assert data.default_value is True

        session.set_management_key(MANAGEMENT_KEY_TYPE.AES192, DEFAULT_MANAGEMENT_KEY)
        data = session.get_management_key_metadata()
        assert data.default_value is False

    @pytest.mark.parametrize("key_type", list(KEY_TYPE))
    def test_slot_metadata_generate(self, session, key_type):
        slot = SLOT.SIGNATURE
        key = generate_key(session, slot, key_type)
        data = session.get_slot_metadata(slot)

        assert data.key_type == key_type
        assert data.pin_policy == PIN_POLICY.ALWAYS
        assert data.touch_policy == TOUCH_POLICY.NEVER
        assert data.generated is True
        assert data.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @pytest.mark.parametrize(
        "key",
        [
            rsa.generate_private_key(65537, 1024, default_backend()),
            rsa.generate_private_key(65537, 2048, default_backend()),
            ec.generate_private_key(ec.SECP256R1(), default_backend()),
            ec.generate_private_key(ec.SECP384R1(), default_backend()),
        ],
    )
    @pytest.mark.parametrize(
        "slot, pin_policy",
        [
            (SLOT.AUTHENTICATION, PIN_POLICY.ONCE),
            (SLOT.SIGNATURE, PIN_POLICY.ALWAYS),
            (SLOT.KEY_MANAGEMENT, PIN_POLICY.ONCE),
            (SLOT.CARD_AUTH, PIN_POLICY.NEVER),
        ],
    )
    def test_slot_metadata_put(self, session, key, slot, pin_policy):
        session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
        session.put_key(slot, key)
        data = session.get_slot_metadata(slot)

        assert data.key_type == KEY_TYPE.from_public_key(key.public_key())
        assert data.pin_policy == pin_policy
        assert data.touch_policy == TOUCH_POLICY.NEVER
        assert data.generated is False
        assert data.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
