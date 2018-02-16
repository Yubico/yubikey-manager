from __future__ import print_function
import unittest
import time
from ykman.util import TRANSPORT
from .on_yubikey.util import (
    destructive_tests_not_activated, missing_mode, not_one_yubikey, ykman_cli,
    URI_HOTP_EXAMPLE, URI_TOTP_EXAMPLE, URI_TOTP_EXAMPLE_B)


@unittest.skipIf(*destructive_tests_not_activated)
@unittest.skipIf(*not_one_yubikey)
class TestYkmanInfo(unittest.TestCase):

    def test_ykman_info(self):
        time.sleep(3)
        info = ykman_cli('info')
        self.assertIn('Device type:', info)
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info)


@unittest.skipIf(*destructive_tests_not_activated)
@unittest.skipIf(*not_one_yubikey)
@unittest.skipIf(*missing_mode(TRANSPORT.OTP))
class TestSlotStatus(unittest.TestCase):

    def test_ykman_slot_info(self):
        info = ykman_cli('slot', 'info')
        self.assertIn('Slot 1:', info)
        self.assertIn('Slot 2:', info)

    def test_ykman_swap_slots(self):
        output = ykman_cli('slot', 'swap', '-f')
        self.assertIn('Swapping slots...', output)
        output = ykman_cli('slot', 'swap', '-f')
        self.assertIn('Swapping slots...', output)


@unittest.skipIf(*destructive_tests_not_activated)
@unittest.skipIf(*not_one_yubikey)
@unittest.skipIf(*missing_mode(TRANSPORT.OTP))
class TestSlotProgramming(unittest.TestCase):

    def test_ykman_program_otp_slot_2(self):
        ykman_cli(
            'slot', 'otp', '2', '--public-id', 'vvccccfiluij',
            '--private-id', '267e0a88949b',
            '--key', 'b8e31ab90bb8830e3c1fe1b483a8e0d4', '-f')
        self._check_slot_2_programmed()

    def test_ykman_program_otp_slot_2_generated(self):
        output = ykman_cli('slot', 'otp', '2', '-f')
        self.assertIn('Using YubiKey serial as public ID', output)
        self.assertIn('Using a randomly generated private ID', output)
        self.assertIn('Using a randomly generated secret key', output)
        self._check_slot_2_programmed()

    def test_ykman_program_otp_slot_2_prompt(self):
        ykman_cli(
            'slot', 'otp', '2',
            input='vvccccfiluij\n'
            '267e0a88949b\nb8e31ab90bb8830e3c1fe1b483a8e0d4\ny\n')
        self._check_slot_2_programmed()

    def test_ykman_program_chalresp_slot_2(self):
        ykman_cli('slot', 'chalresp', '2', 'abba', '-f')
        self._check_slot_2_programmed()
        ykman_cli('slot', 'chalresp', '2', '--totp', 'abba', '-f')
        self._check_slot_2_programmed()
        ykman_cli('slot', 'chalresp', '2', '--touch', 'abba', '-f')
        self._check_slot_2_programmed()

    def test_ykman_program_chalresp_slot_2_generated(self):
        output = ykman_cli('slot', 'chalresp', '2', '-f')
        self.assertIn('Using a randomly generated key', output)
        self._check_slot_2_programmed()

    def test_ykman_program_chalresp_slot_2_prompt(self):
        ykman_cli('slot', 'chalresp', '2', input='abba\ny\n')
        self._check_slot_2_programmed()

    def test_ykman_program_hotp_slot_2(self):
        ykman_cli(
            'slot', 'hotp', '2',
            '27KIZZE3SD7GE2FVJJBAXEI3I6RRTPGM', '-f')
        self._check_slot_2_programmed()

    def test_ykman_program_hotp_slot_2_prompt(self):
        ykman_cli('slot', 'hotp', '2', input='abba\ny\n')
        self._check_slot_2_programmed()

    def test_ykman_program_static_slot_2(self):
        ykman_cli(
            'slot', 'static', '2',
            'higngdukgerjktbbikrhirngtlkkttkb', '-f')
        self._check_slot_2_programmed()

    def test_ykman_program_static_slot_2_prompt(self):
        ykman_cli(
            'slot', 'static', '2',
            input='higngdukgerjktbbikrhirngtlkkttkb\ny\n')
        self._check_slot_2_programmed()

    def test_update_settings_enter_slot_2(self):
        ykman_cli('slot', 'otp', '2', '-f')
        output = ykman_cli('slot', 'settings', '2', '-f', '--no-enter')
        self.assertIn('Updating settings for slot', output)

    def test_delete_slot_2(self):
        ykman_cli('slot', 'otp', '2', '-f')
        output = ykman_cli('slot', 'delete', '2', '-f')
        self.assertIn('Deleting the configuration', output)
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: empty', status)

    def test_access_code_slot_2(self):
        ykman_cli('slot', '--access-code', '111111111111', 'static', '2', '-f')
        self._check_slot_2_programmed()
        ykman_cli('slot', '--access-code', '111111111111', 'delete', '2', '-f')
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: empty', status)

    def _check_slot_2_programmed(self):
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: programmed', status)


@unittest.skipIf(*destructive_tests_not_activated)
@unittest.skipIf(*not_one_yubikey)
@unittest.skipIf(*missing_mode(TRANSPORT.OTP))
class TestSlotCalculate(unittest.TestCase):

    def test_calculate_hex(self):
        ykman_cli('slot', 'delete', '2', '-f')
        ykman_cli('slot', 'chalresp', '2', 'abba', '-f')
        output = ykman_cli('slot', 'calculate', '2', 'abba')
        self.assertIn('f8de2586056d89d8b961a072d1245a495d2155e1', output)

    def test_calculate_totp(self):
        ykman_cli('slot', 'delete', '2', '-f')
        ykman_cli('slot', 'chalresp', '2', 'abba', '-f')
        output = ykman_cli('slot', 'calculate', '2', '999', '-T')
        self.assertEqual('533486', output.strip())
        output = ykman_cli('slot', 'calculate', '2', '999', '-T', '-d', '8')
        self.assertEqual('04533486', output.strip())
        output = ykman_cli('slot', 'calculate', '2', '-T')
        self.assertEqual(6, len(output.strip()))
        output = ykman_cli('slot', 'calculate', '2', '-T', '-d', '8')
        self.assertEqual(8, len(output.strip()))


@unittest.skipIf(*destructive_tests_not_activated)
@unittest.skipIf(*not_one_yubikey)
@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class TestOpenPGP(unittest.TestCase):

    def test_openpgp_info(self):
        output = ykman_cli('openpgp', 'info')
        self.assertIn('OpenPGP version:', output)

    def test_openpgp_reset(self):
        output = ykman_cli('openpgp', 'reset', '-f')
        self.assertIn(
            'Success! All data has been cleared and default PINs are set.',
            output)


@unittest.skipIf(*destructive_tests_not_activated)
@unittest.skipIf(*not_one_yubikey)
@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class TestOATH(unittest.TestCase):

    def test_oath_info(self):
        output = ykman_cli('oath', 'info')
        self.assertIn('version:', output)

    def test_oath_add_credential(self):
        ykman_cli('oath', 'add', 'test-name', 'abba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name', creds)

    def test_oath_add_credential_prompt(self):
        ykman_cli('oath', 'add', 'test-name-2', input='abba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name-2', creds)

    def test_oath_add_credential_with_space(self):
        ykman_cli('oath', 'add', 'test-name-space', 'ab ba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name-space', creds)

    def test_oath_hidden_cred(self):
        ykman_cli('oath', 'add', '_hidden:name', 'abba')
        creds = ykman_cli('oath', 'code')
        self.assertNotIn('_hidden:name', creds)
        creds = ykman_cli('oath', 'code', '-H')
        self.assertIn('_hidden:name', creds)

    def test_oath_add_uri_hotp(self):
        ykman_cli('oath', 'uri', URI_HOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        self.assertIn('Example:demo', creds)

    def test_oath_add_uri_totp(self):
        ykman_cli('oath', 'uri', URI_TOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        self.assertIn('john.doe', creds)

    def test_oath_add_uri_totp_prompt(self):
        ykman_cli('oath', 'uri', input=URI_TOTP_EXAMPLE_B)
        creds = ykman_cli('oath', 'list')
        self.assertIn('john.doe', creds)

    def test_oath_code(self):
        ykman_cli('oath', 'add', 'test-name2', 'abba')
        creds = ykman_cli('oath', 'code')
        self.assertIn('test-name2', creds)

    def test_oath_code_query(self):
        ykman_cli('oath', 'add', 'query-me', 'abba')
        creds = ykman_cli('oath', 'code', 'query-me')
        self.assertIn('query-me', creds)

    def test_oath_reset(self):
        output = ykman_cli('oath', 'reset', '-f')
        self.assertIn('Success! All OATH credentials have been cleared from '
                      'your YubiKey', output)

    def test_oath_hotp_code(self):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'hotp-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'hotp-cred')
        self.assertIn('659165', cred)

    def test_oath_hotp_steam_code(self):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'Steam:steam-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'steam-cred')
        self.assertIn('CGC3K', cred)

    def test_oath_delete(self):
        ykman_cli('oath', 'add', 'delete-me', 'abba')
        ykman_cli('oath', 'delete', 'delete-me', '-f')
        self.assertNotIn('delete-me', ykman_cli('oath', 'list'))
