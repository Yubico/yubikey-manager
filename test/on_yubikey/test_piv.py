from __future__ import unicode_literals

import datetime
import random
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from yubikit.management import USB_INTERFACE
from yubikit.core.smartcard import ApduError
from yubikit.piv import (
    PivSession,
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
from .framework import device_test_suite, yubikey_conditions
from ..util import open_file


DEFAULT_PIN = "123456"
NON_DEFAULT_PIN = "654321"
DEFAULT_PUK = "12345678"
NON_DEFAULT_PUK = "87654321"
DEFAULT_MANAGEMENT_KEY = bytes.fromhex(
    "010203040506070801020304050607080102030405060708"
)  # noqa: E501
NON_DEFAULT_MANAGEMENT_KEY = bytes.fromhex(
    "010103040506070801020304050607080102030405060708"
)  # noqa: E501


now = datetime.datetime.now


def get_test_cert():
    with open_file("rsa_2048_cert.pem") as f:
        return parse_certificates(f.read(), None)[0]


def get_test_key():
    with open_file("rsa_2048_key.pem") as f:
        return parse_private_key(f.read(), None)


def sign(session, slot, key_type, message):
    return session.sign(slot, key_type, message, hashes.SHA256(), padding.PKCS1v15())


@device_test_suite(USB_INTERFACE.CCID)
def additional_tests(open_device):
    class PivTestCase(unittest.TestCase):
        def setUp(self):
            self.conn = open_device()[0]
            self.session = PivSession(self.conn)

        def tearDown(self):
            self.conn.close()

        def assertMgmKeyIs(self, key):
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, key)

        def assertMgmKeyIsNot(self, key):
            with self.assertRaises(ApduError):
                self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, key)

        def assertStoredMgmKeyEquals(self, key):
            pivman_prot = get_pivman_protected_data(self.session)
            self.assertEqual(pivman_prot.key, key)

        def assertStoredMgmKeyNotEquals(self, key):
            pivman_prot = get_pivman_protected_data(self.session)
            self.assertNotEqual(pivman_prot.key, key)

        def reconnect(self):
            self.conn.close()
            self.conn = open_device()[0]
            self.session = PivSession(self.conn)

    class KeyManagement(PivTestCase):
        @classmethod
        def setUpClass(cls):
            with open_device()[0] as conn:
                session = PivSession(conn)
                session.reset()

        def generate_key(self, slot, alg=KEY_TYPE.ECCP256, pin_policy=None):
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            public_key = self.session.generate_key(
                slot, alg, pin_policy=pin_policy, touch_policy=TOUCH_POLICY.NEVER
            )
            self.reconnect()
            return public_key

        @yubikey_conditions.supports_piv_touch_policies
        def test_delete_certificate_requires_authentication(self):
            self.generate_key(SLOT.AUTHENTICATION)

            with self.assertRaises(ApduError):
                self.session.delete_certificate(SLOT.AUTHENTICATION)

            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.delete_certificate(SLOT.AUTHENTICATION)

        def test_generate_csr_works(self):
            public_key = self.generate_key(SLOT.AUTHENTICATION)
            if self.session.version < (4, 0, 0):
                # NEO always has PIN policy "ONCE"
                self.session.verify_pin(DEFAULT_PIN)

            self.session.verify_pin(DEFAULT_PIN)
            csr = generate_csr(self.session, SLOT.AUTHENTICATION, public_key, "alice")

            self.assertEqual(
                csr.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
            self.assertEqual(
                csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                    0
                ].value,  # noqa: E501
                "alice",
            )

        def test_generate_self_signed_certificate_requires_authentication(self):
            public_key = self.generate_key(SLOT.AUTHENTICATION)
            if self.session.version < (4, 0, 0):
                # NEO always has PIN policy "ONCE"
                self.session.verify_pin(DEFAULT_PIN)

            with self.assertRaises(ApduError):
                generate_self_signed_certificate(
                    self.session, SLOT.AUTHENTICATION, public_key, "alice", now(), now()
                )

            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.verify_pin(DEFAULT_PIN)
            generate_self_signed_certificate(
                self.session, SLOT.AUTHENTICATION, public_key, "alice", now(), now()
            )

        def _test_generate_self_signed_certificate(self, slot):
            public_key = self.generate_key(slot)
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.verify_pin(DEFAULT_PIN)
            cert = generate_self_signed_certificate(
                self.session, slot, public_key, "alice", now(), now()
            )

            self.assertEqual(
                cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
            self.assertEqual(
                cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                    0
                ].value,  # noqa: E501
                "alice",
            )

        def test_generate_self_signed_certificate_slot_9a_works(self):
            self._test_generate_self_signed_certificate(SLOT.AUTHENTICATION)

        def test_generate_self_signed_certificate_slot_9c_works(self):
            self._test_generate_self_signed_certificate(SLOT.SIGNATURE)

        def test_generate_key_requires_authentication(self):
            with self.assertRaises(ApduError):
                self.session.generate_key(
                    SLOT.AUTHENTICATION,
                    KEY_TYPE.ECCP256,
                    touch_policy=TOUCH_POLICY.NEVER,
                )

            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.generate_key(
                SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, touch_policy=TOUCH_POLICY.NEVER
            )

        def test_put_certificate_requires_authentication(self):
            cert = get_test_cert()
            with self.assertRaises(ApduError):
                self.session.put_certificate(SLOT.AUTHENTICATION, cert)

            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.put_certificate(SLOT.AUTHENTICATION, cert)

        def _test_put_key_pairing(self, alg1, alg2):
            # Set up a key in the slot and create a certificate for it
            public_key = self.generate_key(
                SLOT.AUTHENTICATION, alg=alg1, pin_policy=PIN_POLICY.NEVER
            )
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            cert = generate_self_signed_certificate(
                self.session,
                SLOT.AUTHENTICATION,
                public_key,
                "test",
                datetime.datetime.now(),
                datetime.datetime.now(),
            )
            self.session.put_certificate(SLOT.AUTHENTICATION, cert)
            self.assertTrue(
                check_key(self.session, SLOT.AUTHENTICATION, cert.public_key())
            )

            cert2 = self.session.get_certificate(SLOT.AUTHENTICATION)
            self.assertEqual(cert, cert2)

            self.session.delete_certificate(SLOT.AUTHENTICATION)

            # Overwrite the key with one of the same type
            self.generate_key(
                SLOT.AUTHENTICATION, alg=alg1, pin_policy=PIN_POLICY.NEVER
            )
            self.assertFalse(
                check_key(self.session, SLOT.AUTHENTICATION, cert.public_key())
            )

            # Overwrite the key with one of a different type
            self.generate_key(
                SLOT.AUTHENTICATION, alg=alg2, pin_policy=PIN_POLICY.NEVER
            )
            self.assertFalse(
                check_key(self.session, SLOT.AUTHENTICATION, cert.public_key())
            )

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_put_certificate_verifies_key_pairing_rsa1024(self):
            self._test_put_key_pairing(KEY_TYPE.RSA1024, KEY_TYPE.ECCP256)

        @yubikey_conditions.is_not_roca
        def test_put_certificate_verifies_key_pairing_rsa2048(self):
            self._test_put_key_pairing(KEY_TYPE.RSA2048, KEY_TYPE.ECCP256)

        def test_put_certificate_verifies_key_pairing_eccp256(self):
            self._test_put_key_pairing(KEY_TYPE.ECCP256, KEY_TYPE.ECCP384)

        def test_put_certificate_verifies_key_pairing_eccp384(self):
            self._test_put_key_pairing(KEY_TYPE.ECCP384, KEY_TYPE.ECCP256)

        def test_put_key_requires_authentication(self):
            private_key = get_test_key()
            with self.assertRaises(ApduError):
                self.session.put_key(SLOT.AUTHENTICATION, private_key)

            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.put_key(SLOT.AUTHENTICATION, private_key)

        def test_get_certificate_does_not_require_authentication(self):
            cert = get_test_cert()
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.put_certificate(SLOT.AUTHENTICATION, cert)

            self.reconnect()

            cert = self.session.get_certificate(SLOT.AUTHENTICATION)
            self.assertIsNotNone(cert)

    class ManagementKeyReadOnly(PivTestCase):
        """
        Tests after which the management key is always the default management
        key. Placing compatible tests here reduces the amount of slow reset
        calls needed.
        """

        @classmethod
        def setUpClass(cls):
            with open_device()[0] as conn:
                PivSession(conn).reset()

        def test_authenticate_twice_does_not_throw(self):
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)

        def test_reset_resets_has_stored_key_flag(self):
            pivman = get_pivman_data(self.session)
            self.assertFalse(pivman.has_stored_key)

            self.session.verify_pin(DEFAULT_PIN)
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            pivman_set_mgm_key(
                self.session,
                NON_DEFAULT_MANAGEMENT_KEY,
                MANAGEMENT_KEY_TYPE.TDES,
                store_on_device=True,
            )

            pivman = get_pivman_data(self.session)
            self.assertTrue(pivman.has_stored_key)

            self.reconnect()
            self.session.reset()

            pivman = get_pivman_data(self.session)
            self.assertFalse(pivman.has_stored_key)

        # Should this really fail?
        def disabled_test_reset_while_verified_throws_nice_ValueError(self):
            self.session.verify_pin(DEFAULT_PIN)
            with self.assertRaises(ValueError) as cm:
                self.session.reset()
            self.assertTrue(
                "Cannot read remaining tries from status word: 9000"
                in str(cm.exception)
            )

        def test_set_mgm_key_does_not_change_key_if_not_authenticated(self):
            with self.assertRaises(ApduError):
                self.session.set_management_key(
                    MANAGEMENT_KEY_TYPE.TDES, NON_DEFAULT_MANAGEMENT_KEY
                )
            self.assertMgmKeyIs(DEFAULT_MANAGEMENT_KEY)

        @yubikey_conditions.version_min((3, 5, 0))
        def test_set_stored_mgm_key_does_not_destroy_key_if_pin_not_verified(
            self,
        ):  # noqa: E501
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            with self.assertRaises(ApduError):
                pivman_set_mgm_key(
                    self.session,
                    NON_DEFAULT_MANAGEMENT_KEY,
                    MANAGEMENT_KEY_TYPE.TDES,
                    store_on_device=True,
                )

            self.assertMgmKeyIs(DEFAULT_MANAGEMENT_KEY)

    class ManagementKeyReadWrite(PivTestCase):
        """
        Tests after which the management key may not be the default management
        key.
        """

        def setUp(self):
            PivTestCase.setUp(self)
            self.session.reset()

        def test_set_mgm_key_changes_mgm_key(self):
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.set_management_key(
                MANAGEMENT_KEY_TYPE.TDES, NON_DEFAULT_MANAGEMENT_KEY
            )

            self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
            self.assertMgmKeyIs(NON_DEFAULT_MANAGEMENT_KEY)

        def test_set_stored_mgm_key_succeeds_if_pin_is_verified(self):
            self.session.verify_pin(DEFAULT_PIN)
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            pivman_set_mgm_key(
                self.session,
                NON_DEFAULT_MANAGEMENT_KEY,
                MANAGEMENT_KEY_TYPE.TDES,
                store_on_device=True,
            )

            self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
            self.assertMgmKeyIs(NON_DEFAULT_MANAGEMENT_KEY)
            self.assertStoredMgmKeyEquals(NON_DEFAULT_MANAGEMENT_KEY)

            pivman_prot = get_pivman_protected_data(self.session)
            self.assertMgmKeyIs(pivman_prot.key)

    class Operations(PivTestCase):
        def setUp(self):
            PivTestCase.setUp(self)
            self.session.reset()

        def generate_key(self, pin_policy=None):
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            public_key = self.session.generate_key(
                SLOT.AUTHENTICATION,
                KEY_TYPE.ECCP256,
                pin_policy=pin_policy,
                touch_policy=TOUCH_POLICY.NEVER,
            )
            self.reconnect()
            return public_key

        @yubikey_conditions.supports_piv_pin_policies
        def test_sign_with_pin_policy_always_requires_pin_every_time(self):
            self.generate_key(pin_policy=PIN_POLICY.ALWAYS)

            with self.assertRaises(ApduError):
                sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

            self.session.verify_pin(DEFAULT_PIN)
            sig = sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
            self.assertIsNotNone(sig)

            with self.assertRaises(ApduError):
                sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

            self.session.verify_pin(DEFAULT_PIN)
            sig = sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
            self.assertIsNotNone(sig)

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.supports_piv_pin_policies
        def test_sign_with_pin_policy_never_does_not_require_pin(self):
            self.generate_key(pin_policy=PIN_POLICY.NEVER)
            sig = sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
            self.assertIsNotNone(sig)

        @yubikey_conditions.is_fips
        def test_pin_policy_never_blocked_on_fips(self):
            with self.assertRaises(ApduError):
                self.generate_key(pin_policy=PIN_POLICY.NEVER)

        def test_sign_with_pin_policy_once_requires_pin_once_per_session(self):
            self.generate_key(pin_policy=PIN_POLICY.ONCE)

            with self.assertRaises(ApduError):
                sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

            self.session.verify_pin(DEFAULT_PIN)
            sig = sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
            self.assertIsNotNone(sig)

            sig = sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
            self.assertIsNotNone(sig)

            self.reconnect()

            with self.assertRaises(ApduError):
                sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")

            self.session.verify_pin(DEFAULT_PIN)
            sig = sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
            self.assertIsNotNone(sig)

            sig = sign(self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b"foo")
            self.assertIsNotNone(sig)

        def test_signature_can_be_verified_by_public_key(self):
            public_key = self.generate_key(pin_policy=PIN_POLICY.ONCE)

            signed_data = bytes(random.randint(0, 255) for i in range(32))

            self.session.verify_pin(DEFAULT_PIN)
            sig = sign(
                self.session, SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, signed_data,
            )
            self.assertIsNotNone(sig)

            public_key.verify(sig, signed_data, ec.ECDSA(hashes.SHA256()))

    class UnblockPin(PivTestCase):
        def setUp(self):
            super().setUp()
            self.session.reset()

        def block_pin(self):
            while self.session.get_pin_attempts() > 0:
                try:
                    self.session.verify_pin(NON_DEFAULT_PIN)
                except Exception:
                    pass

        def test_unblock_pin_requires_no_previous_authentication(self):
            self.session.unblock_pin(DEFAULT_PUK, NON_DEFAULT_PIN)

        def test_unblock_pin_with_wrong_puk_throws_WrongPuk(self):
            with self.assertRaises(InvalidPinError):
                self.session.unblock_pin(NON_DEFAULT_PUK, NON_DEFAULT_PIN)

        def test_unblock_pin_resets_pin_and_retries(self):
            self.session.reset()
            self.reconnect()

            self.block_pin()

            with self.assertRaises(InvalidPinError):
                self.session.verify_pin(DEFAULT_PIN)

            self.session.unblock_pin(DEFAULT_PUK, NON_DEFAULT_PIN)

            self.assertEqual(self.session.get_pin_attempts(), 3)
            self.session.verify_pin(NON_DEFAULT_PIN)

        def test_set_pin_retries_requires_pin_and_mgm_key(self):
            # Fails with no authentication
            with self.assertRaises(ApduError):
                self.session.set_pin_attempts(4, 4)

            # Fails with only PIN
            self.session.verify_pin(DEFAULT_PIN)
            with self.assertRaises(ApduError):
                self.session.set_pin_attempts(4, 4)

            self.reconnect()

            # Fails with only management key
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            with self.assertRaises(ApduError):
                self.session.set_pin_attempts(4, 4)

            # Succeeds with both PIN and management key
            self.session.verify_pin(DEFAULT_PIN)
            self.session.set_pin_attempts(4, 4)

        def test_set_pin_retries_sets_pin_and_puk_tries(self):
            pin_tries = 9
            puk_tries = 7

            self.session.verify_pin(DEFAULT_PIN)
            self.session.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)
            self.session.set_pin_attempts(pin_tries, puk_tries)

            c1 = self.session
            self.reconnect()
            c2 = self.session

            self.assertNotEqual(c1, c2)

            self.assertEqual(self.session.get_pin_attempts(), pin_tries)
            with self.assertRaises(InvalidPinError) as ctx:
                self.session.change_puk(NON_DEFAULT_PUK, DEFAULT_PUK)
            self.assertEqual(ctx.exception.attempts_remaining, puk_tries - 1)

    return [
        KeyManagement,
        ManagementKeyReadOnly,
        ManagementKeyReadWrite,
        Operations,
        UnblockPin,
    ]
