from __future__ import unicode_literals

import datetime
import unittest
from binascii import a2b_hex
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from ykman.driver_ccid import APDUError
from ykman.piv import (ALGO, PIN_POLICY, PivController, SLOT, TOUCH_POLICY)
from ykman.util import TRANSPORT, parse_certificate, parse_private_key
from .util import (
    DestructiveYubikeyTestCase, missing_mode, open_device, get_version, is_fips)
from ..util import open_file


DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_PUK = '12345678'
NON_DEFAULT_PUK = '87654321'
DEFAULT_MANAGEMENT_KEY = a2b_hex('010203040506070801020304050607080102030405060708')  # noqa: E501
NON_DEFAULT_MANAGEMENT_KEY = a2b_hex('010103040506070801020304050607080102030405060708')  # noqa: E501


now = datetime.datetime.now

no_pin_policy = (get_version() is not None and get_version() < (4, 0, 0),
                 'PIN policies not supported.')


def get_test_cert():
    with open_file('rsa_2048_cert.pem') as f:
        return parse_certificate(f.read(), None)


def get_test_key():
    with open_file('rsa_2048_key.pem') as f:
        return parse_private_key(f.read(), None)


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class PivTestCase(DestructiveYubikeyTestCase):

    def setUp(self):
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.controller = PivController(self.dev.driver)

    def tearDown(self):
        self.dev.driver.close()

    def assertMgmKeyIs(self, key):
        self.controller.authenticate(key)

    def assertMgmKeyIsNot(self, key):
        with self.assertRaises(APDUError):
            self.controller.authenticate(key)

    def assertStoredMgmKeyEquals(self, key):
        self.assertEqual(self.controller._pivman_protected_data.key, key)

    def assertStoredMgmKeyNotEquals(self, key):
        self.assertNotEqual(self.controller._pivman_protected_data.key, key)

    def reconnect(self):
        self.dev.driver.close()
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.controller = PivController(self.dev.driver)


class KeyManagement(PivTestCase):

    @classmethod
    def setUpClass(cls):
        with open_device(transports=TRANSPORT.CCID) as dev:
            controller = PivController(dev.driver)
            controller.reset()

    def generate_key(self, slot):
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        public_key = self.controller.generate_key(
            slot, ALGO.ECCP256, touch_policy=TOUCH_POLICY.NEVER)
        self.reconnect()
        return public_key

    def test_delete_certificate_requires_authentication(self):
        self.generate_key(SLOT.AUTHENTICATION)

        with self.assertRaises(APDUError):
            self.controller.delete_certificate(SLOT.AUTHENTICATION)

        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.delete_certificate(SLOT.AUTHENTICATION)

    def test_generate_csr_works(self):
        public_key = self.generate_key(SLOT.AUTHENTICATION)
        if get_version() < (4, 0, 0):
            # NEO always has PIN policy "ONCE"
            self.controller.verify(DEFAULT_PIN)

        self.controller.verify(DEFAULT_PIN)
        csr = self.controller.generate_certificate_signing_request(
            SLOT.AUTHENTICATION, public_key, 'alice')

        self.assertEqual(
            csr.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo),
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo),
        )
        self.assertEqual(
            csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,  # noqa: E501
            'alice'
        )

    def test_generate_self_signed_certificate_requires_authentication(self):
        public_key = self.generate_key(SLOT.AUTHENTICATION)
        if get_version() < (4, 0, 0):
            # NEO always has PIN policy "ONCE"
            self.controller.verify(DEFAULT_PIN)

        with self.assertRaises(APDUError):
            self.controller.generate_self_signed_certificate(
                SLOT.AUTHENTICATION, public_key, 'alice', now(), now())

        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.verify(DEFAULT_PIN)
        self.controller.generate_self_signed_certificate(
            SLOT.AUTHENTICATION, public_key, 'alice', now(), now())

    def _test_generate_self_signed_certificate(self, slot):
        public_key = self.generate_key(slot)
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.verify(DEFAULT_PIN)
        self.controller.generate_self_signed_certificate(
            slot, public_key, 'alice', now(), now())

        cert = self.controller.read_certificate(slot)

        self.assertEqual(
            cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo),
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo),
        )
        self.assertEqual(
            cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,  # noqa: E501
            'alice'
        )

    def test_generate_self_signed_certificate_slot_9a_works(self):
        self._test_generate_self_signed_certificate(SLOT.AUTHENTICATION)

    def test_generate_self_signed_certificate_slot_9c_works(self):
        self._test_generate_self_signed_certificate(SLOT.SIGNATURE)

    def test_generate_key_requires_authentication(self):
        with self.assertRaises(APDUError):
            self.controller.generate_key(SLOT.AUTHENTICATION, ALGO.ECCP256,
                                         touch_policy=TOUCH_POLICY.NEVER)

        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.generate_key(SLOT.AUTHENTICATION, ALGO.ECCP256,
                                     touch_policy=TOUCH_POLICY.NEVER)

    def test_import_certificate_requires_authentication(self):
        cert = get_test_cert()
        with self.assertRaises(APDUError):
            self.controller.import_certificate(SLOT.AUTHENTICATION, cert)

        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.import_certificate(SLOT.AUTHENTICATION, cert)

    def test_import_key_requires_authentication(self):
        private_key = get_test_key()
        with self.assertRaises(APDUError):
            self.controller.import_key(SLOT.AUTHENTICATION, private_key)

        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.import_key(SLOT.AUTHENTICATION, private_key)

    def test_read_certificate_does_not_require_authentication(self):
        cert = get_test_cert()
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.import_certificate(SLOT.AUTHENTICATION, cert)

        self.reconnect()

        cert = self.controller.read_certificate(SLOT.AUTHENTICATION)
        self.assertIsNotNone(cert)


class ManagementKeyReadOnly(PivTestCase):
    """
    Tests after which the management key is always the default management key.
    Placing compatible tests here reduces the amount of slow reset calls needed.
    """

    @classmethod
    def setUpClass(cls):
        with open_device(transports=TRANSPORT.CCID) as dev:
            PivController(dev.driver).reset()

    def test_authenticate_twice_does_not_throw(self):
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)

    def test_reset_resets_has_stored_key_flag(self):
        self.assertFalse(self.controller.has_stored_key)

        self.controller.verify(DEFAULT_PIN)
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.set_mgm_key(None, store_on_device=True)

        self.assertTrue(self.controller.has_stored_key)

        self.reconnect()
        self.controller.reset()

        self.assertFalse(self.controller.has_stored_key)

    def test_reset_while_verified_throws_nice_ValueError(self):
        self.controller.verify(DEFAULT_PIN)
        with self.assertRaises(ValueError) as cm:
            self.controller.reset()
        self.assertTrue('Failed reading remaining' in str(cm.exception))

    def test_set_mgm_key_does_not_change_key_if_not_authenticated(self):
        with self.assertRaises(APDUError):
            self.controller.set_mgm_key(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(DEFAULT_MANAGEMENT_KEY)

    @unittest.skipIf(get_version() is not None and get_version() < (3, 5, 0),
                     'Known fixed bug')
    def test_set_stored_mgm_key_does_not_destroy_key_if_pin_not_verified(self):
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        with self.assertRaises(APDUError):
            self.controller.set_mgm_key(None, store_on_device=True)

        self.assertMgmKeyIs(DEFAULT_MANAGEMENT_KEY)


class ManagementKeyReadWrite(PivTestCase):
    """
    Tests after which the management key may not be the default management key.
    """

    def setUp(self):
        PivTestCase.setUp(self)
        self.controller.reset()

    def test_set_mgm_key_changes_mgm_key(self):
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.set_mgm_key(NON_DEFAULT_MANAGEMENT_KEY)

        self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(NON_DEFAULT_MANAGEMENT_KEY)

    def test_set_stored_mgm_key_succeeds_if_pin_is_verified(self):
        self.controller.verify(DEFAULT_PIN)
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.set_mgm_key(NON_DEFAULT_MANAGEMENT_KEY,
                                    store_on_device=True)

        self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertStoredMgmKeyEquals(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(self.controller._pivman_protected_data.key)

    def test_set_stored_random_mgm_key_succeeds_if_pin_is_verified(self):
        self.controller.verify(DEFAULT_PIN)
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.set_mgm_key(None, store_on_device=True)

        self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIsNot(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(self.controller._pivman_protected_data.key)
        self.assertStoredMgmKeyNotEquals(DEFAULT_MANAGEMENT_KEY)
        self.assertStoredMgmKeyNotEquals(NON_DEFAULT_MANAGEMENT_KEY)


class Operations(PivTestCase):

    def setUp(self):
        PivTestCase.setUp(self)
        self.controller.reset()

    def generate_key(self, pin_policy=None):
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        public_key = self.controller.generate_key(
            SLOT.AUTHENTICATION, ALGO.ECCP256, pin_policy=pin_policy,
            touch_policy=TOUCH_POLICY.NEVER)
        self.reconnect()
        return public_key

    @unittest.skipIf(*no_pin_policy)
    def test_sign_with_pin_policy_always_requires_pin_every_time(self):
        self.generate_key(pin_policy=PIN_POLICY.ALWAYS)

        with self.assertRaises(APDUError):
            self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')

        self.controller.verify(DEFAULT_PIN)
        sig = self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')
        self.assertIsNotNone(sig)

        with self.assertRaises(APDUError):
            self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')

        self.controller.verify(DEFAULT_PIN)
        sig = self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')
        self.assertIsNotNone(sig)

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    @unittest.skipIf(*no_pin_policy)
    def test_sign_with_pin_policy_never_does_not_require_pin(self):
        self.generate_key(pin_policy=PIN_POLICY.NEVER)
        sig = self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')
        self.assertIsNotNone(sig)

    @unittest.skipIf(not is_fips(), 'YubiKey FIPS required.')
    def test_pin_policy_never_blocked_on_fips(self):
        with self.assertRaises(APDUError):
            self.generate_key(pin_policy=PIN_POLICY.NEVER)

    def test_sign_with_pin_policy_once_requires_pin_once_per_session(self):
        self.generate_key(pin_policy=PIN_POLICY.ONCE)

        with self.assertRaises(APDUError):
            self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')

        self.controller.verify(DEFAULT_PIN)
        sig = self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')
        self.assertIsNotNone(sig)

        sig = self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')
        self.assertIsNotNone(sig)

        self.reconnect()

        with self.assertRaises(APDUError):
            self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')

        self.controller.verify(DEFAULT_PIN)
        sig = self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')
        self.assertIsNotNone(sig)

        sig = self.controller.sign(SLOT.AUTHENTICATION, ALGO.ECCP256, b'foo')
        self.assertIsNotNone(sig)


class UnblockPin(PivTestCase):

    @classmethod
    def setUpClass(cls):
        with open_device(transports=TRANSPORT.CCID) as dev:
            controller = PivController(dev.driver)
            controller.reset()

    def block_pin(self):
        while self.controller.get_pin_tries() > 0:
            try:
                self.controller.verify(NON_DEFAULT_PIN)
            except Exception:
                pass

    def test_unblock_pin_requires_no_previous_authentication(self):
        self.controller.unblock_pin(DEFAULT_PUK, NON_DEFAULT_PIN)

    def test_unblock_pin_with_wrong_puk_throws_ValueError(self):
        with self.assertRaises(ValueError):
            self.controller.unblock_pin(NON_DEFAULT_PUK, NON_DEFAULT_PIN)

    def test_unblock_pin_resets_pin_and_retries(self):
        self.controller.reset()
        self.reconnect()

        self.controller.verify(DEFAULT_PIN, NON_DEFAULT_PIN)
        self.reconnect()

        self.block_pin()

        with self.assertRaises(ValueError):
            self.controller.verify(DEFAULT_PIN)

        self.controller.unblock_pin(DEFAULT_PUK, NON_DEFAULT_PIN)

        self.assertEqual(self.controller.get_pin_tries(), 3)
        self.controller.verify(NON_DEFAULT_PIN)

    def test_set_pin_retries_requires_pin_and_mgm_key(self):
        # Fails with no authentication
        with self.assertRaises(APDUError):
            self.controller.set_pin_retries(4, 4)

        # Fails with only PIN
        self.controller.verify(DEFAULT_PIN)
        with self.assertRaises(APDUError):
            self.controller.set_pin_retries(4, 4)

        self.reconnect()

        # Fails with only management key
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        with self.assertRaises(APDUError):
            self.controller.set_pin_retries(4, 4)

        # Succeeds with both PIN and management key
        self.controller.verify(DEFAULT_PIN)
        self.controller.set_pin_retries(4, 4)

    def test_set_pin_retries_sets_pin_and_puk_tries(self):
        pin_tries = 9
        puk_tries = 7

        self.controller.verify(DEFAULT_PIN)
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.set_pin_retries(pin_tries, puk_tries)

        self.reconnect()

        self.assertEqual(self.controller.get_pin_tries(), pin_tries)
        self.assertEqual(self.controller._get_puk_tries(), puk_tries - 1)
