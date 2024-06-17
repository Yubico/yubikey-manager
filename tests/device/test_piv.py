import datetime
import random
import pytest
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, x25519

from yubikit.core import NotSupportedError, TRANSPORT
from yubikit.core.smartcard import AID, ApduError
from yubikit.management import CAPABILITY, ManagementSession
from yubikit.piv import (
    PivSession,
    ALGORITHM,
    KEY_TYPE,
    PIN_POLICY,
    TOUCH_POLICY,
    SLOT,
    OBJECT_ID,
    MANAGEMENT_KEY_TYPE,
    InvalidPinError,
    _do_check_key_support,
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
from ..util import open_file
from . import condition
from typing import NamedTuple


DEFAULT_PIN = "123456"
NON_DEFAULT_PIN = "12341235"
DEFAULT_PUK = "12345678"
NON_DEFAULT_PUK = "12341236"
DEFAULT_MANAGEMENT_KEY = bytes.fromhex(
    "010203040506070801020304050607080102030405060708"
)
NON_DEFAULT_MANAGEMENT_KEY = bytes.fromhex(
    "010103040506070801020304050607080102030405060708"
)

NOW = datetime.datetime.now()

SIGN_KEY_TYPES = list(set(KEY_TYPE) - {KEY_TYPE.X25519})
ECDH_KEY_TYPES = [KEY_TYPE.ECCP256, KEY_TYPE.ECCP384, KEY_TYPE.X25519]


def get_test_cert():
    with open_file("rsa_2048_cert.pem") as f:
        return parse_certificates(f.read(), None)[0]


def get_test_key():
    with open_file("rsa_2048_key.pem") as f:
        return parse_private_key(f.read(), None)


@pytest.fixture
def scp(info, transport, scp_params):
    if transport == TRANSPORT.NFC and CAPABILITY.PIV in info.fips_capable:
        return scp_params
    return None


@pytest.fixture
@condition.capability(CAPABILITY.PIV)
def session(ccid_connection, scp, info):
    if CAPABILITY.PIV in info.reset_blocked:
        mgmt = ManagementSession(ccid_connection)
        mgmt.device_reset()
        piv = PivSession(ccid_connection, scp)
    else:
        piv = PivSession(ccid_connection, scp)
        piv.reset()
    yield piv
    reset_state(piv, scp)


class Keys(NamedTuple):
    pin: str
    puk: str
    mgmt: bytes


@pytest.fixture
def default_keys():
    yield Keys(DEFAULT_PIN, DEFAULT_PUK, DEFAULT_MANAGEMENT_KEY)


@pytest.fixture
def keys(session, info, default_keys, scp):
    if info.pin_complexity:
        new_keys = Keys(
            "12345679" if CAPABILITY.PIV in info.fips_capable else "123458",
            "12345670",
            bytes.fromhex("010203040506070801020304050607080102030405060709"),
        )
        session.change_pin(default_keys.pin, new_keys.pin)
        session.change_puk(default_keys.puk, new_keys.puk)
        session.authenticate(default_keys.mgmt)
        session.set_management_key(session.management_key_type, new_keys.mgmt)
        reset_state(session, scp)

        yield new_keys
    else:
        yield default_keys


def not_roca(version):
    return not ((4, 2, 0) <= version < (4, 3, 5))


def reset_state(session, scp_params):
    session.protocol.connection.connection.disconnect()
    session.protocol.connection.connection.connect()
    session.protocol.select(AID.PIV)
    if scp_params:
        session.protocol.init_scp(scp_params)


def assert_mgm_key_is(session, key):
    session.authenticate(key)


def assert_mgm_key_is_not(session, key):
    with pytest.raises(ApduError):
        session.authenticate(key)


def generate_key(
    session,
    scp,
    keys,
    slot=SLOT.AUTHENTICATION,
    key_type=KEY_TYPE.ECCP256,
    pin_policy=PIN_POLICY.DEFAULT,
):
    session.authenticate(keys.mgmt)
    key = session.generate_key(slot, key_type, pin_policy=pin_policy)
    reset_state(session, scp)
    return key


def generate_sw_key(key_type):
    if key_type.algorithm == ALGORITHM.RSA:
        return rsa.generate_private_key(65537, key_type.bit_len, default_backend())
    elif key_type == KEY_TYPE.ECCP256:
        return ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif key_type == KEY_TYPE.ECCP384:
        return ec.generate_private_key(ec.SECP384R1(), default_backend())
    elif key_type == KEY_TYPE.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    elif key_type == KEY_TYPE.X25519:
        return x25519.X25519PrivateKey.generate()


def import_key(
    session,
    scp,
    keys,
    slot=SLOT.AUTHENTICATION,
    key_type=KEY_TYPE.ECCP256,
    pin_policy=PIN_POLICY.DEFAULT,
):
    private_key = generate_sw_key(key_type)
    session.authenticate(keys.mgmt)
    session.put_key(slot, private_key, pin_policy)
    reset_state(session, scp)
    return private_key.public_key()


def verify_cert_signature(cert, public_key=None):
    if not public_key:
        public_key = cert.public_key

    args = [cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm]
    key_type = KEY_TYPE.from_public_key(public_key)
    if key_type.algorithm == ALGORITHM.RSA:
        args.insert(2, padding.PKCS1v15())
    elif key_type == KEY_TYPE.ED25519:
        args.pop()
    else:
        args[2] = ec.ECDSA(args[2])
    public_key.verify(*args)


def skip_unsupported_key_type(key_type, info, pin_policy=PIN_POLICY.DEFAULT):
    try:
        _do_check_key_support(
            info.version,
            key_type,
            pin_policy,
            TOUCH_POLICY.DEFAULT,
            fips_restrictions=CAPABILITY.PIV in info.fips_capable,
        )
    except NotSupportedError as e:
        pytest.skip(f"{e}")


class TestCertificateSignatures:
    @pytest.mark.parametrize("key_type", SIGN_KEY_TYPES)
    @pytest.mark.parametrize(
        "hash_algorithm", (hashes.SHA256, hashes.SHA384, hashes.SHA512)
    )
    def test_generate_self_signed_certificate(
        self, info, session, key_type, hash_algorithm, keys, scp
    ):
        skip_unsupported_key_type(key_type, info)

        slot = SLOT.SIGNATURE
        public_key = import_key(session, scp, keys, slot, key_type)
        session.authenticate(keys.mgmt)
        session.verify_pin(keys.pin)
        cert = generate_self_signed_certificate(
            session, slot, public_key, "CN=alice", NOW, NOW, hash_algorithm
        )

        if key_type == KEY_TYPE.ED25519:
            assert cert.public_key() == public_key
        else:
            assert cert.public_key().public_numbers() == public_key.public_numbers()
        verify_cert_signature(cert, public_key)


class TestDecrypt:
    @pytest.mark.parametrize(
        "key_type",
        [KEY_TYPE.RSA1024, KEY_TYPE.RSA2048, KEY_TYPE.RSA3072, KEY_TYPE.RSA4096],
    )
    def test_import_decrypt(self, session, info, key_type, keys, scp):
        skip_unsupported_key_type(key_type, info)

        public_key = import_key(
            session, scp, keys, SLOT.KEY_MANAGEMENT, key_type=key_type
        )
        pt = os.urandom(32)
        ct = public_key.encrypt(pt, padding.PKCS1v15())

        session.verify_pin(keys.pin)
        pt2 = session.decrypt(SLOT.KEY_MANAGEMENT, ct, padding.PKCS1v15())
        assert pt == pt2


class TestKeyAgreement:
    @pytest.mark.parametrize("key_type", ECDH_KEY_TYPES)
    def test_generate_ecdh(self, session, info, key_type, keys, scp):
        skip_unsupported_key_type(key_type, info)

        e_priv = generate_sw_key(key_type)
        public_key = generate_key(
            session, scp, keys, SLOT.KEY_MANAGEMENT, key_type=key_type
        )
        if key_type == KEY_TYPE.X25519:
            args = (public_key,)
        else:
            args = (ec.ECDH(), public_key)

        shared1 = e_priv.exchange(*args)
        session.verify_pin(keys.pin)
        shared2 = session.calculate_secret(SLOT.KEY_MANAGEMENT, e_priv.public_key())
        assert shared1 == shared2

    @pytest.mark.parametrize("key_type", ECDH_KEY_TYPES)
    def test_import_ecdh(self, session, info, key_type, keys, scp):
        skip_unsupported_key_type(key_type, info)

        e_priv = generate_sw_key(key_type)
        public_key = import_key(
            session, scp, keys, SLOT.KEY_MANAGEMENT, key_type=key_type
        )
        if key_type == KEY_TYPE.X25519:
            args = (public_key,)
        else:
            args = (ec.ECDH(), public_key)

        shared1 = e_priv.exchange(*args)
        session.verify_pin(keys.pin)
        shared2 = session.calculate_secret(SLOT.KEY_MANAGEMENT, e_priv.public_key())
        assert shared1 == shared2


class TestKeyManagement:
    def test_delete_certificate_requires_authentication(self, session, keys, scp):
        generate_key(session, scp, keys, SLOT.AUTHENTICATION)

        with pytest.raises(ApduError):
            session.delete_certificate(SLOT.AUTHENTICATION)

        session.authenticate(keys.mgmt)
        session.delete_certificate(SLOT.AUTHENTICATION)

    def test_generate_csr_works(self, session, keys, scp):
        public_key = generate_key(session, scp, keys, SLOT.AUTHENTICATION)

        session.verify_pin(keys.pin)
        csr = generate_csr(session, SLOT.AUTHENTICATION, public_key, "CN=alice")

        assert csr.public_key().public_numbers() == public_key.public_numbers()
        assert (
            csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            == "alice"
        )

    def test_generate_self_signed_certificate_requires_pin(self, session, keys, scp):
        session.verify_pin(keys.pin)
        public_key = generate_key(session, scp, keys, SLOT.AUTHENTICATION)

        with pytest.raises(ApduError):
            generate_self_signed_certificate(
                session, SLOT.AUTHENTICATION, public_key, "CN=alice", NOW, NOW
            )

        session.verify_pin(keys.pin)
        generate_self_signed_certificate(
            session, SLOT.AUTHENTICATION, public_key, "CN=alice", NOW, NOW
        )

    @pytest.mark.parametrize("slot", (SLOT.SIGNATURE, SLOT.AUTHENTICATION))
    def test_generate_self_signed_certificate(self, session, slot, keys, scp):
        public_key = generate_key(session, scp, keys, slot)
        session.authenticate(keys.mgmt)
        session.verify_pin(keys.pin)
        cert = generate_self_signed_certificate(
            session, slot, public_key, "CN=alice", NOW, NOW
        )

        assert cert.public_key().public_numbers() == public_key.public_numbers()
        assert (
            cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            == "alice"
        )

    def test_generate_key_requires_authentication(self, session, keys):
        with pytest.raises(ApduError):
            session.generate_key(
                SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, touch_policy=TOUCH_POLICY.DEFAULT
            )

        session.authenticate(keys.mgmt)
        session.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)

    def test_put_certificate_requires_authentication(self, session, keys):
        cert = get_test_cert()
        with pytest.raises(ApduError):
            session.put_certificate(SLOT.AUTHENTICATION, cert)

        session.authenticate(keys.mgmt)
        session.put_certificate(SLOT.AUTHENTICATION, cert)

    def _test_put_key_pairing(self, session, scp, keys, alg1, alg2):
        # Set up a key in the slot and create a certificate for it
        public_key = generate_key(
            session, scp, keys, SLOT.AUTHENTICATION, key_type=alg1
        )
        session.authenticate(keys.mgmt)
        session.verify_pin(keys.pin)
        cert = generate_self_signed_certificate(
            session, SLOT.AUTHENTICATION, public_key, "CN=test", NOW, NOW
        )
        session.put_certificate(SLOT.AUTHENTICATION, cert)
        assert check_key(session, SLOT.AUTHENTICATION, cert.public_key())

        cert2 = session.get_certificate(SLOT.AUTHENTICATION)
        assert cert == cert2

        session.delete_certificate(SLOT.AUTHENTICATION)

        # Overwrite the key with one of the same type
        generate_key(session, scp, keys, SLOT.AUTHENTICATION, key_type=alg1)
        session.verify_pin(keys.pin)
        assert not check_key(session, SLOT.AUTHENTICATION, cert.public_key())

        # Overwrite the key with one of a different type
        generate_key(session, scp, keys, SLOT.AUTHENTICATION, key_type=alg2)
        session.verify_pin(keys.pin)
        assert not check_key(session, SLOT.AUTHENTICATION, cert.public_key())

    @condition.check(not_roca)
    @condition.yk4_fips(False)
    def test_put_certificate_verifies_key_pairing_rsa1024(
        self, session, keys, info, scp
    ):
        if CAPABILITY.PIV in info.fips_capable:
            pytest.skip("RSA1024 not available on YubiKey FIPS")
        self._test_put_key_pairing(
            session, scp, keys, KEY_TYPE.RSA1024, KEY_TYPE.ECCP256
        )

    @condition.check(not_roca)
    def test_put_certificate_verifies_key_pairing_rsa2048(self, session, keys, scp):
        self._test_put_key_pairing(
            session, scp, keys, KEY_TYPE.RSA2048, KEY_TYPE.ECCP256
        )

    @condition.check(not_roca)
    def test_put_certificate_verifies_key_pairing_eccp256_a(self, session, keys, scp):
        self._test_put_key_pairing(
            session, scp, keys, KEY_TYPE.ECCP256, KEY_TYPE.RSA2048
        )

    @condition.min_version(4)
    def test_put_certificate_verifies_key_pairing_eccp256_b(self, session, keys, scp):
        self._test_put_key_pairing(
            session, scp, keys, KEY_TYPE.ECCP256, KEY_TYPE.ECCP384
        )

    @condition.min_version(4)
    def test_put_certificate_verifies_key_pairing_eccp384(self, session, keys, scp):
        self._test_put_key_pairing(
            session, scp, keys, KEY_TYPE.ECCP384, KEY_TYPE.ECCP256
        )

    def test_put_key_requires_authentication(self, session, keys):
        private_key = get_test_key()
        with pytest.raises(ApduError):
            session.put_key(SLOT.AUTHENTICATION, private_key)

        session.authenticate(keys.mgmt)
        session.put_key(SLOT.AUTHENTICATION, private_key)

    def test_get_certificate_does_not_require_authentication(self, session, keys, scp):
        cert = get_test_cert()
        session.authenticate(keys.mgmt)
        session.put_certificate(SLOT.AUTHENTICATION, cert)
        reset_state(session, scp)

        assert session.get_certificate(SLOT.AUTHENTICATION)


class TestCompressedCertificate:
    def test_put_and_read_compressed_certificate(self, session, keys):
        session.authenticate(keys.mgmt)
        cert = get_test_cert()
        session.put_certificate(SLOT.AUTHENTICATION, cert)
        session.put_certificate(SLOT.SIGNATURE, cert, compress=True)
        assert session.get_certificate(SLOT.AUTHENTICATION) == session.get_certificate(
            SLOT.SIGNATURE
        )
        obj1 = session.get_object(OBJECT_ID.from_slot(SLOT.AUTHENTICATION))
        obj2 = session.get_object(OBJECT_ID.from_slot(SLOT.SIGNATURE))
        assert obj1 != obj2
        assert len(obj1) > len(obj2)


class TestManagementKeyReadOnly:
    """
    Tests after which the management key is always the default management
    key. Placing compatible tests here reduces the amount of slow reset
    calls needed.
    """

    def test_authenticate_twice_does_not_throw(self, session, keys):
        session.authenticate(keys.mgmt)
        session.authenticate(keys.mgmt)

    def test_reset_resets_has_stored_key_flag(self, session, keys, scp):
        pivman = get_pivman_data(session)
        assert not pivman.has_stored_key

        session.verify_pin(keys.pin)
        session.authenticate(keys.mgmt)
        pivman_set_mgm_key(
            session,
            NON_DEFAULT_MANAGEMENT_KEY,
            session.management_key_type,
            store_on_device=True,
        )

        pivman = get_pivman_data(session)
        assert pivman.has_stored_key

        reset_state(session, scp)
        session.reset()

        pivman = get_pivman_data(session)
        assert not pivman.has_stored_key

    # Should this really fail?
    def disabled_test_reset_while_verified_throws_nice_ValueError(self, session, keys):
        session.verify_pin(keys.pin)
        with pytest.raises(ValueError) as cm:
            session.reset()
        assert "Cannot read remaining tries from status word: 9000" in str(cm.exception)

    def test_set_mgm_key_does_not_change_key_if_not_authenticated(self, session, keys):
        with pytest.raises(ApduError):
            session.set_management_key(
                session.management_key_type, NON_DEFAULT_MANAGEMENT_KEY
            )
        assert_mgm_key_is(session, keys.mgmt)

    @condition.min_version(3, 5)
    def test_set_stored_mgm_key_does_not_destroy_key_if_pin_not_verified(
        self, session, keys
    ):
        session.authenticate(keys.mgmt)
        with pytest.raises(ApduError):
            pivman_set_mgm_key(
                session,
                NON_DEFAULT_MANAGEMENT_KEY,
                session.management_key_type,
                store_on_device=True,
            )

        assert_mgm_key_is(session, keys.mgmt)


class TestManagementKeyReadWrite:
    """
    Tests after which the management key may not be the default management
    key.
    """

    def test_set_mgm_key_changes_mgm_key(self, session, keys):
        session.authenticate(keys.mgmt)
        session.set_management_key(
            session.management_key_type, NON_DEFAULT_MANAGEMENT_KEY
        )

        assert_mgm_key_is_not(session, keys.mgmt)
        assert_mgm_key_is(session, NON_DEFAULT_MANAGEMENT_KEY)

    def test_set_stored_mgm_key_succeeds_if_pin_is_verified(self, session, keys):
        session.verify_pin(keys.pin)
        session.authenticate(keys.mgmt)
        pivman_set_mgm_key(
            session,
            NON_DEFAULT_MANAGEMENT_KEY,
            session.management_key_type,
            store_on_device=True,
        )

        assert_mgm_key_is_not(session, keys.mgmt)
        assert_mgm_key_is(session, NON_DEFAULT_MANAGEMENT_KEY)

        pivman_prot = get_pivman_protected_data(session)
        assert pivman_prot.key == NON_DEFAULT_MANAGEMENT_KEY

        pivman_prot = get_pivman_protected_data(session)
        assert_mgm_key_is(session, pivman_prot.key)


def sign(session, slot, key_type, message):
    return session.sign(slot, key_type, message, hashes.SHA256(), padding.PKCS1v15())


class TestOperations:
    @condition.min_version(4)
    def test_sign_with_pin_policy_always_requires_pin_every_time(
        self, session, keys, scp
    ):
        generate_key(session, scp, keys, pin_policy=PIN_POLICY.ALWAYS)

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(keys.pin)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(keys.pin)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

    @condition.yk4_fips(False)
    @condition.check(lambda info: CAPABILITY.PIV not in info.fips_capable)
    @condition.min_version(4)
    def test_sign_with_pin_policy_never_does_not_require_pin(self, session, keys, scp):
        generate_key(session, scp, keys, pin_policy=PIN_POLICY.NEVER)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

    @condition.yk4_fips(True)
    def test_pin_policy_never_blocked_on_fips(self, session, keys, scp):
        with pytest.raises(NotSupportedError):
            generate_key(session, scp, keys, pin_policy=PIN_POLICY.NEVER)

    @condition.min_version(4)
    def test_sign_with_pin_policy_once_requires_pin_once_per_session(
        self, session, keys, scp
    ):
        generate_key(session, scp, keys, pin_policy=PIN_POLICY.ONCE)

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(keys.pin)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        reset_state(session, scp)

        with pytest.raises(ApduError):
            sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

        session.verify_pin(keys.pin)
        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

        sig = sign(session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
        assert sig

    def test_signature_can_be_verified_by_public_key(self, session, keys, scp):
        public_key = generate_key(session, scp, keys)

        signed_data = bytes(random.randint(0, 255) for i in range(32))

        session.verify_pin(keys.pin)
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
    @pytest.fixture(autouse=True)
    def preconditions(self, bio_metadata):
        if bio_metadata:
            pytest.skip("PUK not supported on this YubiKey")

    def test_unblock_pin_requires_no_previous_authentication(self, session, keys):
        session.unblock_pin(keys.puk, NON_DEFAULT_PIN)

    def test_unblock_pin_with_wrong_puk_throws_InvalidPinError(self, session):
        with pytest.raises(InvalidPinError):
            session.unblock_pin(NON_DEFAULT_PUK, NON_DEFAULT_PIN)

    def test_unblock_pin_resets_pin_and_retries(self, session, keys):
        block_pin(session)

        with pytest.raises(InvalidPinError):
            session.verify_pin(keys.pin)

        session.unblock_pin(keys.puk, NON_DEFAULT_PIN)

        assert session.get_pin_attempts() == 3
        session.verify_pin(NON_DEFAULT_PIN)

    def test_set_pin_retries_requires_pin_and_mgm_key(
        self, session, version, default_keys, scp
    ):
        keys = default_keys

        # Fails with no authentication
        with pytest.raises(ApduError):
            session.set_pin_attempts(4, 4)

        # Fails with only PIN
        session.verify_pin(keys.pin)
        with pytest.raises(ApduError):
            session.set_pin_attempts(4, 4)

        reset_state(session, scp)

        session.authenticate(keys.mgmt)
        # Fails with only management key (requirement added in 0.1.3)
        if version >= (0, 1, 3):
            with pytest.raises(ApduError):
                session.set_pin_attempts(4, 4)

        # Succeeds with both PIN and management key
        session.verify_pin(keys.pin)
        session.set_pin_attempts(4, 4)

    def test_set_pin_retries_sets_pin_and_puk_tries(self, session, default_keys, scp):
        keys = default_keys
        pin_tries = 9
        puk_tries = 7

        session.verify_pin(keys.pin)
        session.authenticate(keys.mgmt)
        session.set_pin_attempts(pin_tries, puk_tries)

        reset_state(session, scp)

        assert session.get_pin_attempts() == pin_tries
        with pytest.raises(InvalidPinError) as ctx:
            session.change_puk(NON_DEFAULT_PUK, keys.puk)
        assert ctx.value.attempts_remaining == puk_tries - 1


class TestMetadata:
    @pytest.fixture(autouse=True)
    @condition.min_version(5, 3)
    def preconditions(self):
        pass

    def test_pin_metadata(self, session, bio_metadata):
        data = session.get_pin_metadata()
        assert data.default_value is True
        assert data.total_attempts == 8 if bio_metadata else 3
        assert data.attempts_remaining == data.total_attempts

    def test_management_key_metadata(self, session, info):
        data = session.get_management_key_metadata()
        default_type = data.key_type
        if info.version < (5, 7, 0):
            assert data.key_type == MANAGEMENT_KEY_TYPE.TDES
        else:
            assert data.key_type == MANAGEMENT_KEY_TYPE.AES192
        assert data.default_value is True
        assert data.touch_policy is TOUCH_POLICY.NEVER

        session.authenticate(DEFAULT_MANAGEMENT_KEY)
        session.set_management_key(
            MANAGEMENT_KEY_TYPE.AES192, NON_DEFAULT_MANAGEMENT_KEY
        )
        assert session.management_key_type == MANAGEMENT_KEY_TYPE.AES192

        data = session.get_management_key_metadata()
        assert data.key_type == MANAGEMENT_KEY_TYPE.AES192
        assert data.default_value is False
        assert data.touch_policy is TOUCH_POLICY.NEVER

        session.set_management_key(default_type, DEFAULT_MANAGEMENT_KEY)
        data = session.get_management_key_metadata()
        assert data.default_value is True

        if CAPABILITY.PIV not in info.fips_capable:
            session.set_management_key(
                MANAGEMENT_KEY_TYPE.TDES, NON_DEFAULT_MANAGEMENT_KEY
            )
            data = session.get_management_key_metadata()
            assert data.default_value is False

        session.reset()
        assert session.management_key_type == default_type

    @pytest.mark.parametrize("key_type", list(KEY_TYPE))
    def test_slot_metadata_generate(self, session, info, keys, key_type, scp):
        skip_unsupported_key_type(key_type, info)

        slot = SLOT.SIGNATURE
        key = generate_key(session, scp, keys, slot, key_type)
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
    def test_slot_metadata_put(self, session, info, keys, key, slot, pin_policy):
        key_type = KEY_TYPE.from_public_key(key.public_key())
        skip_unsupported_key_type(key_type, info, pin_policy)
        session.authenticate(keys.mgmt)
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


class TestMoveAndDelete:
    @pytest.fixture(autouse=True)
    @condition.min_version(5, 7)
    def preconditions(self):
        pass

    def test_move_key(self, session, keys):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        session.authenticate(keys.mgmt)
        session.put_key(SLOT.AUTHENTICATION, key)
        data_a = session.get_slot_metadata(SLOT.AUTHENTICATION)

        session.move_key(SLOT.AUTHENTICATION, SLOT.SIGNATURE)
        data_s = session.get_slot_metadata(SLOT.SIGNATURE)

        assert data_a == data_s
        with pytest.raises(ApduError):
            session.get_slot_metadata(SLOT.AUTHENTICATION)

    def test_delete_key(self, session, keys):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        session.authenticate(keys.mgmt)
        session.put_key(SLOT.AUTHENTICATION, key)
        session.get_slot_metadata(SLOT.AUTHENTICATION)

        session.delete_key(SLOT.AUTHENTICATION)
        with pytest.raises(ApduError):
            session.get_slot_metadata(SLOT.AUTHENTICATION)


class TestPinComplexity:
    @pytest.fixture(autouse=True)
    def preconditions(self, info):
        if not info.pin_complexity:
            pytest.skip("Requires YubiKey with PIN complexity enabled")

    @pytest.mark.parametrize("pin", ("111111", "22222222", "333333", "4444444"))
    def test_repeated_pins(self, session, keys, pin):
        with pytest.raises(ApduError):
            session.change_pin(keys.pin, pin)

    @pytest.mark.parametrize("pin", ("abc123", "password", "123123"))
    def test_invalid_pins(self, session, keys, pin):
        with pytest.raises(ApduError):
            session.change_pin(keys.pin, pin)


@pytest.fixture
def bio_metadata(session):
    try:
        return session.get_bio_metadata()
    except NotSupportedError:
        return None


class TestBioMpe:
    @pytest.fixture(autouse=True)
    def preconditions(self, bio_metadata):
        if not bio_metadata:
            pytest.skip("Requires YubiKey Bio with PIV")

    def test_verify_uv_without_fingerprints(self, session, bio_metadata):
        with pytest.raises(InvalidPinError):
            session.verify_uv(check_only=True)
