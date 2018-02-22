import unittest
from binascii import a2b_hex
from ykman.driver_ccid import APDUError
from ykman.piv import PivController
from ykman.util import TRANSPORT
from .util import (DestructiveYubikeyTestCase, missing_mode, open_device)


DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_PUK = '12345678'
NON_DEFAULT_PUK = '87654321'
DEFAULT_MANAGEMENT_KEY = '010203040506070801020304050607080102030405060708'
NON_DEFAULT_MANAGEMENT_KEY = '010103040506070801020304050607080102030405060708'


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class PivTestCase(DestructiveYubikeyTestCase):
    pass


class ManagementKey(PivTestCase):

    def setUp(self):
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.ctrl = PivController(self.dev.driver)
        self.ctrl.reset()
        self.dev.driver.close()

        # Need to reopen to update flags after reset
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.ctrl = PivController(self.dev.driver)

    def tearDown(self):
        self.dev.driver.close()

    def reconnect(self):
        self.dev.driver.close()
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.ctrl = PivController(self.dev.driver)

    def assertMgmKeyIs(self, key):
        if type(key) is str:
            key = a2b_hex(key)
        self.ctrl.authenticate(key)

    def assertMgmKeyIsNot(self, key):
        if type(key) is str:
            key = a2b_hex(key)

        with self.assertRaises(APDUError):
            self.ctrl.authenticate(key)

    def assertStoredMgmKeyEquals(self, key):
        if type(key) is str:
            key = a2b_hex(key)
        self.assertEqual(self.ctrl._pivman_protected_data.key, key)

    def assertStoredMgmKeyNotEquals(self, key):
        if type(key) is str:
            key = a2b_hex(key)
        self.assertNotEqual(self.ctrl._pivman_protected_data.key, key)

    def test_authenticate_twice_does_not_throw(self):
        self.ctrl.authenticate(a2b_hex(DEFAULT_MANAGEMENT_KEY))
        self.ctrl.authenticate(a2b_hex(DEFAULT_MANAGEMENT_KEY))

    def test_reset_while_verified_throws_nice_ValueError(self):
        self.ctrl.verify(DEFAULT_PIN)
        with self.assertRaisesRegex(ValueError, '^Failed reading remaining'):
            self.ctrl.reset()

    def test_reset_resets_has_stored_key_flag(self):
        self.assertFalse(self.ctrl.has_stored_key)

        self.ctrl.verify(DEFAULT_PIN)
        self.ctrl.authenticate(a2b_hex(DEFAULT_MANAGEMENT_KEY))
        self.ctrl.set_mgm_key(None, store_on_device=True)

        self.assertTrue(self.ctrl.has_stored_key)

        self.reconnect()
        self.ctrl.reset()

        self.assertFalse(self.ctrl.has_stored_key)

    def test_set_mgm_key_changes_mgm_key(self):
        self.ctrl.authenticate(a2b_hex(DEFAULT_MANAGEMENT_KEY))
        self.ctrl.set_mgm_key(a2b_hex(NON_DEFAULT_MANAGEMENT_KEY))

        self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(NON_DEFAULT_MANAGEMENT_KEY)

    def test_set_mgm_key_does_not_change_key_if_not_authenticated(self):
        with self.assertRaises(APDUError):
            self.ctrl.set_mgm_key(a2b_hex(NON_DEFAULT_MANAGEMENT_KEY))
        self.assertMgmKeyIs(DEFAULT_MANAGEMENT_KEY)

    def test_set_stored_mgm_key_does_not_destroy_key_if_pin_not_verified(self):
        self.ctrl.authenticate(a2b_hex(DEFAULT_MANAGEMENT_KEY))
        with self.assertRaises(APDUError):
            self.ctrl.set_mgm_key(None, store_on_device=True)

        self.assertMgmKeyIs(DEFAULT_MANAGEMENT_KEY)

    def test_set_stored_mgm_key_succeeds_if_pin_is_verified(self):
        self.ctrl.verify(DEFAULT_PIN)
        self.ctrl.authenticate(a2b_hex(DEFAULT_MANAGEMENT_KEY))
        self.ctrl.set_mgm_key(a2b_hex(NON_DEFAULT_MANAGEMENT_KEY),
                              store_on_device=True)

        self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertStoredMgmKeyEquals(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(self.ctrl._pivman_protected_data.key)

    def test_set_stored_random_mgm_key_succeeds_if_pin_is_verified(self):
        self.ctrl.verify(DEFAULT_PIN)
        self.ctrl.authenticate(a2b_hex(DEFAULT_MANAGEMENT_KEY))
        self.ctrl.set_mgm_key(None, store_on_device=True)

        self.assertMgmKeyIsNot(DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIsNot(NON_DEFAULT_MANAGEMENT_KEY)
        self.assertMgmKeyIs(self.ctrl._pivman_protected_data.key)
        self.assertStoredMgmKeyNotEquals(DEFAULT_MANAGEMENT_KEY)
        self.assertStoredMgmKeyNotEquals(NON_DEFAULT_MANAGEMENT_KEY)
