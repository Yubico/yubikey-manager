import unittest

from fido2.ctap1 import ApduError
from yubikit.core import USB_INTERFACE
from yubikit.core.smartcard import SW
from ykman.fido import fips_change_pin, fips_verify_pin, fips_reset, is_in_fips_mode
from .framework import device_test_suite, yubikey_conditions


@device_test_suite(USB_INTERFACE.FIDO)
def additional_tests(open_device):
    @yubikey_conditions.is_fips
    class TestFipsU2fCommands(unittest.TestCase):
        def setUp(self):
            self.conn = open_device()[0]

        def tearDown(self):
            self.conn.close()

        def test_pin_commands(self):
            # Assumes PIN is 012345 or not set at beginning of test

            # Make sure PIN is 012345
            try:
                fips_verify_pin(self.conn, "012345")
                fips_change_pin(self.conn, "012345", "012345")
            except ApduError as e:
                if e.code == SW.VERIFY_FAIL_NO_RETRY:
                    self.skipTest("PIN set to something other than 012345")
                elif e.code == SW.AUTH_METHOD_BLOCKED:
                    self.skipTest("PIN blocked")
                elif e.code == SW.COMMAND_NOT_ALLOWED:
                    fips_change_pin(self.conn, None, "012345")

            # Verify with correct PIN
            fips_verify_pin(self.conn, "012345")

            # Change the PIN, verify, then change back
            fips_change_pin(self.conn, "012345", "012012")
            fips_verify_pin(self.conn, "012012")
            fips_change_pin(self.conn, "012012", "012345")

            # Verify with incorrect PIN
            with self.assertRaises(ApduError) as cm:
                fips_verify_pin(self.conn, "543210")
            self.assertEqual(SW.VERIFY_FAIL_NO_RETRY, cm.exception.code)

            # Verify with correct PIN
            fips_verify_pin(self.conn, "012345")

        def test_reset_command(self):
            try:
                fips_reset(self.conn)
            except ApduError as e:
                self.assertIn(
                    e.code, [SW.COMMAND_NOT_ALLOWED, SW.CONDITIONS_NOT_SATISFIED]
                )

        def test_verify_fips_mode_command(self):
            is_in_fips_mode(self.conn)

    return [TestFipsU2fCommands]
