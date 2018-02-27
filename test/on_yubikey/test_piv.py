import unittest
from binascii import a2b_hex
from ykman.driver_ccid import APDUError
from ykman.piv import (ALGO, PIN_POLICY, PivController, SLOT, TOUCH_POLICY)
from ykman.util import TRANSPORT
from .util import (DestructiveYubikeyTestCase, missing_mode, open_device)


DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_PUK = '12345678'
NON_DEFAULT_PUK = '87654321'
DEFAULT_MANAGEMENT_KEY = a2b_hex('010203040506070801020304050607080102030405060708')  # noqa: E501
NON_DEFAULT_MANAGEMENT_KEY = a2b_hex('010103040506070801020304050607080102030405060708')  # noqa: E501


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class PivTestCase(DestructiveYubikeyTestCase):

    def setUp(self):
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.controller = PivController(self.dev.driver)

    def tearDown(self):
        self.dev.driver.close()

    def assertMgmKeyIs(self, key):
        if type(key) is str:
            key = a2b_hex(key)
        self.controller.authenticate(key)

    def assertMgmKeyIsNot(self, key):
        if type(key) is str:
            key = a2b_hex(key)

        with self.assertRaises(APDUError):
            self.controller.authenticate(key)

    def assertStoredMgmKeyEquals(self, key):
        if type(key) is str:
            key = a2b_hex(key)
        self.assertEqual(self.controller._pivman_protected_data.key, key)

    def assertStoredMgmKeyNotEquals(self, key):
        if type(key) is str:
            key = a2b_hex(key)
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

    def generate_key(self):
        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.generate_key(SLOT.AUTHENTICATION, ALGO.ECCP256,
                                     pin_policy=PIN_POLICY.NEVER,
                                     touch_policy=TOUCH_POLICY.NEVER)
        self.reconnect()

    def test_delete_certificate_requires_authentication(self):
        self.generate_key()

        with self.assertRaises(APDUError):
            self.controller.delete_certificate(SLOT.AUTHENTICATION)

        self.controller.authenticate(DEFAULT_MANAGEMENT_KEY)
        self.controller.delete_certificate(SLOT.AUTHENTICATION)


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
        with self.assertRaisesRegex(ValueError, '^Failed reading remaining'):
            self.controller.reset()

    def test_set_mgm_key_does_not_change_key_if_not_authenticated(self):
        with self.assertRaises(APDUError):
            self.controller.set_mgm_key(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(DEFAULT_MANAGEMENT_KEY)

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
