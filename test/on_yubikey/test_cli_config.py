import time
import unittest
from .framework import cli_test_suite, yubikey_conditions


VALID_LOCK_CODE = 'a' * 32
INVALID_LOCK_CODE_NON_HEX = 'z' * 32


@cli_test_suite
def additional_tests(ykman_cli):

    @yubikey_conditions.can_write_config
    class TestConfigUSB(unittest.TestCase):

        def setUp(self):
            ykman_cli('config', 'usb', '--enable-all', '-f')

        def tearDown(self):
            ykman_cli('config', 'usb', '--enable-all', '-f')

        def test_disable_otp(self):
            ykman_cli('config', 'usb', '--disable', 'OTP', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('OTP', output)

        def test_disable_u2f(self):
            ykman_cli('config', 'usb', '--disable', 'U2F', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('FIDO U2F', output)

        def test_disable_openpgp(self):
            ykman_cli('config', 'usb', '--disable', 'OPGP', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('OpenPGP', output)

        def test_disable_openpgp_alternative_syntax(self):
            ykman_cli('config', 'usb', '--disable', 'openpgp', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('OpenPGP', output)

        def test_disable_piv(self):
            ykman_cli('config', 'usb', '--disable', 'PIV', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('PIV', output)

        def test_disable_oath(self):
            ykman_cli('config', 'usb', '--disable', 'OATH', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('OATH', output)

        def test_disable_fido2(self):
            ykman_cli('config', 'usb', '--disable', 'FIDO2', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('FIDO2', output)

        def test_disable_and_enable(self):
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'usb', '--disable', 'FIDO2', '--enable',
                    'FIDO2', '-f')
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'usb', '--enable-all', '--disable', 'FIDO2', '-f')

        def test_disable_all(self):
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'usb', '-d', 'FIDO2', '-d', 'U2F', '-d',
                    'OATH', '-d', 'OPGP', 'PIV', '-d', 'OTP')

        def test_mode_command(self):
            ykman_cli('mode', 'ccid', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('FIDO U2F', output)
            self.assertNotIn('FIDO2', output)
            self.assertNotIn('OTP', output)

            ykman_cli('mode', 'otp', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('FIDO U2F', output)
            self.assertNotIn('FIDO2', output)
            self.assertNotIn('OpenPGP', output)
            self.assertNotIn('PIV', output)
            self.assertNotIn('OATH', output)

            ykman_cli('mode', 'fido', '-f')
            output = ykman_cli('config', 'usb', '--list')
            self.assertNotIn('OTP', output)
            self.assertNotIn('OATH', output)
            self.assertNotIn('PIV', output)
            self.assertNotIn('OpenPGP', output)

            # Prevent communication errors in other tests
            time.sleep(1)

    @yubikey_conditions.can_write_config
    class TestConfigNFC(unittest.TestCase):

        def setUp(self):
            ykman_cli('config', 'nfc', '--enable-all', '-f')

        def tearDown(self):
            ykman_cli('config', 'nfc', '--enable-all', '-f')

        def test_disable_otp(self):
            ykman_cli('config', 'nfc', '--disable', 'OTP', '-f')
            output = ykman_cli('config', 'nfc', '--list')
            self.assertNotIn('OTP', output)

        def test_disable_u2f(self):
            ykman_cli('config', 'nfc', '--disable', 'U2F', '-f')
            output = ykman_cli('config', 'nfc', '--list')
            self.assertNotIn('FIDO U2F', output)

        def test_disable_openpgp(self):
            ykman_cli('config', 'nfc', '--disable', 'OPGP', '-f')
            output = ykman_cli('config', 'nfc', '--list')
            self.assertNotIn('OpenPGP', output)

        def test_disable_piv(self):
            ykman_cli('config', 'nfc', '--disable', 'PIV', '-f')
            output = ykman_cli('config', 'nfc', '--list')
            self.assertNotIn('PIV', output)

        def test_disable_oath(self):
            ykman_cli('config', 'nfc', '--disable', 'OATH', '-f')
            output = ykman_cli('config', 'nfc', '--list')
            self.assertNotIn('OATH', output)

        def test_disable_fido2(self):
            ykman_cli('config', 'nfc', '--disable', 'FIDO2', '-f')
            output = ykman_cli('config', 'nfc', '--list')
            self.assertNotIn('FIDO2', output)

        def test_disable_all(self):
            ykman_cli('config', 'nfc', '--disable-all', '-f')
            output = ykman_cli('config', 'nfc', '--list')
            self.assertFalse(output)

        def test_disable_and_enable(self):
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'nfc', '--disable', 'FIDO2',
                    '--enable', 'FIDO2', '-f')
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'nfc', '--disable-all', '--enable', 'FIDO2', '-f')
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'nfc', '--enable-all', '--disable', 'FIDO2', '-f')
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'nfc', '--enable-all', '--disable-all',
                    'FIDO2', '-f')

    @yubikey_conditions.can_write_config
    class TestConfigLockCode(unittest.TestCase):

        def test_set_lock_code(self):
            ykman_cli(
                'config', 'set-lock-code', '--new-lock-code', VALID_LOCK_CODE)
            output = ykman_cli('info')
            self.assertIn(
                'Configured applications are protected by a lock code', output)
            ykman_cli(
                'config', 'set-lock-code', '-l', VALID_LOCK_CODE, '--clear')
            output = ykman_cli('info')
            self.assertNotIn(
                'Configured applications are protected by a lock code', output)

        def test_set_invalid_lock_code(self):

            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'set-lock-code',
                    '--new-lock-code', 'aaaa')

            with self.assertRaises(SystemExit):
                ykman_cli(
                    'config', 'set-lock-code',
                    '--new-lock-code', INVALID_LOCK_CODE_NON_HEX)

    return [
        TestConfigUSB,
        TestConfigNFC,
        TestConfigLockCode,
    ]
