import unittest
from ykman.util import TRANSPORT
from .util import (DestructiveYubikeyTestCase, missing_mode, ykman_cli)


@unittest.skipIf(*missing_mode(TRANSPORT.OTP))
class TestSlotStatus(DestructiveYubikeyTestCase):

    def test_ykman_slot_info(self):
        info = ykman_cli('slot', 'info')
        self.assertIn('Slot 1:', info)
        self.assertIn('Slot 2:', info)

    def test_ykman_swap_slots(self):
        output = ykman_cli('slot', 'swap', '-f')
        self.assertIn('Swapping slots...', output)
        output = ykman_cli('slot', 'swap', '-f')
        self.assertIn('Swapping slots...', output)


@unittest.skipIf(*missing_mode(TRANSPORT.OTP))
class TestSlotStaticPassword(DestructiveYubikeyTestCase):

    def setUp(self):
        ykman_cli('slot', 'delete', '2', '-f')

    def tearDown(self):
        ykman_cli('slot', 'delete', '2', '-f')

    def test_provide_pw(self):
        with self.assertRaises(SystemExit):
            ykman_cli(
                'slot', 'static', '2',
                'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        with self.assertRaises(ValueError):
            ykman_cli('slot', 'static', '2', 'ö')
        with self.assertRaises(ValueError):
            ykman_cli('slot', 'static', '2', '@')

        ykman_cli(
            'slot', 'static', '2',
            'higngdukgerjktbbikrhirngtlkkttkb')
        self.assertIn('Slot 2: programmed', ykman_cli('slot', 'info'))

    def test_provide_pw_prompt(self):
        ykman_cli(
            'slot', 'static', '2',
            input='higngdukgerjktbbikrhirngtlkkttkb\ny\n')
        self.assertIn('Slot 2: programmed', ykman_cli('slot', 'info'))

    def test_generate_pw(self):
        with self.assertRaises(SystemExit):
            ykman_cli('slot', 'static', '2', '--generate', '--length', '39')
        with self.assertRaises(SystemExit):
            ykman_cli('slot', 'static', '2', '--generate', '--length')
        with self.assertRaises(SystemExit):
            ykman_cli('slot', 'static', '2', '--generate', '--length', '0')
        with self.assertRaises(SystemExit):
            ykman_cli('slot', 'static', '2', '--generate')
        ykman_cli('slot', 'static', '2', '--generate', '--length', '38')
        self.assertIn('Slot 2: programmed', ykman_cli('slot', 'info'))

    def test_us_scancodes(self):
        ykman_cli('slot', 'static', '2', 'abcABC123', '--scancodes', 'US')
        ykman_cli('slot', 'static', '2', '@!)', '-f', '--scancodes', 'US')

    def test_de_scancodes(self):
        ykman_cli('slot', 'static', '2', 'abcABC123', '--scancodes', 'DE')
        ykman_cli('slot', 'static', '2', 'Üßö', '-f', '--scancodes', 'DE')

    def test_overwrite_prompt(self):
        ykman_cli('slot', 'static', '2', 'bbb')
        with self.assertRaises(SystemExit):
            ykman_cli('slot', 'static', '2', 'ccc')
        ykman_cli('slot', 'static', '2', 'ddd', '-f')
        self.assertIn('Slot 2: programmed', ykman_cli('slot', 'info'))


@unittest.skipIf(*missing_mode(TRANSPORT.OTP))
class TestSlotProgramming(DestructiveYubikeyTestCase):

    def setUp(self):
        ykman_cli('slot', 'delete', '2', '-f')

    def tearDown(self):
        ykman_cli('slot', 'delete', '2', '-f')

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
        ykman_cli(
            'slot', '--access-code', '111111111111', 'static', '2',
            '--generate', '--length', '10')
        self._check_slot_2_programmed()
        ykman_cli('slot', '--access-code', '111111111111', 'delete', '2', '-f')
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: empty', status)

    def _check_slot_2_programmed(self):
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: programmed', status)


@unittest.skipIf(*missing_mode(TRANSPORT.OTP))
class TestSlotCalculate(DestructiveYubikeyTestCase):

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
