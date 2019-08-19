#  vim: set fileencoding=utf-8 :

# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import unittest
from .framework import cli_test_suite, yubikey_conditions


@cli_test_suite
def additional_tests(ykman_cli):

    class TestSlotStatus(unittest.TestCase):

        def test_ykman_otp_info(self):
            info = ykman_cli('otp', 'info')
            self.assertIn('Slot 1:', info)
            self.assertIn('Slot 2:', info)

        def test_ykman_swap_slots(self):
            output = ykman_cli('otp', 'swap', '-f')
            self.assertIn('Swapping slots...', output)
            output = ykman_cli('otp', 'swap', '-f')
            self.assertIn('Swapping slots...', output)

        @yubikey_conditions.is_not_fips
        def test_ykman_otp_info_does_not_indicate_fips_mode_for_non_fips_key(self):  # noqa: E501
            info = ykman_cli('otp', 'info')
            self.assertNotIn('FIPS Approved Mode:', info)

    class TestSlotStaticPassword(unittest.TestCase):

        def setUp(self):
            ykman_cli('otp', 'delete', '2', '-f')

        def tearDown(self):
            ykman_cli('otp', 'delete', '2', '-f')

        def test_too_long(self):
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'otp', 'static', '2',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

        def test_unsupported_chars(self):
            with self.assertRaises(ValueError):
                ykman_cli('otp', 'static', '2', 'ö')
            with self.assertRaises(ValueError):
                ykman_cli('otp', 'static', '2', '@')

        def test_provide_valid_pw(self):
            ykman_cli(
                'otp', 'static', '2',
                'higngdukgerjktbbikrhirngtlkkttkb')
            self.assertIn('Slot 2: programmed', ykman_cli('otp', 'info'))

        def test_provide_valid_pw_prompt(self):
            ykman_cli(
                'otp', 'static', '2',
                input='higngdukgerjktbbikrhirngtlkkttkb\ny\n')
            self.assertIn('Slot 2: programmed', ykman_cli('otp', 'info'))

        def test_generate_pw_too_long(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'static', '2', '--generate', '--length', '39')

        def test_generate_pw_no_length(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'static', '2', '--generate', '--length')
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'static', '2', '--generate')

        def test_generate_zero_length(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'static', '2', '--generate', '--length', '0')

        def test_generate_pw(self):
            ykman_cli('otp', 'static', '2', '--generate', '--length', '38')
            self.assertIn('Slot 2: programmed', ykman_cli('otp', 'info'))

        def test_us_scancodes(self):
            ykman_cli('otp', 'static', '2', 'abcABC123',
                      '--keyboard-layout', 'US')
            ykman_cli('otp', 'static', '2', '@!)', '-f',
                      '--keyboard-layout', 'US')

        def test_de_scancodes(self):
            ykman_cli('otp', 'static', '2', 'abcABC123',
                      '--keyboard-layout', 'DE')
            ykman_cli('otp', 'static', '2', 'Üßö', '-f',
                      '--keyboard-layout', 'DE')

        def test_overwrite_prompt(self):
            ykman_cli('otp', 'static', '2', 'bbb')
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'static', '2', 'ccc')
            ykman_cli('otp', 'static', '2', 'ddd', '-f')
            self.assertIn('Slot 2: programmed', ykman_cli('otp', 'info'))

    class TestSlotProgramming(unittest.TestCase):

        def setUp(self):
            ykman_cli('otp', 'delete', '2', '-f')

        def tearDown(self):
            ykman_cli('otp', 'delete', '2', '-f')

        def test_ykman_program_otp_slot_2(self):
            ykman_cli(
                'otp', 'yubiotp', '2', '--public-id', 'vvccccfiluij',
                '--private-id', '267e0a88949b',
                '--key', 'b8e31ab90bb8830e3c1fe1b483a8e0d4', '-f')
            self._check_slot_2_programmed()

        def test_ykman_program_otp_slot_2_prompt(self):
            ykman_cli(
                'otp', 'yubiotp', '2',
                input='vvccccfiluij\n'
                '267e0a88949b\n'
                'b8e31ab90bb8830e3c1fe1b483a8e0d4\n'
                'n\n'
                'y\n')
            self._check_slot_2_programmed()

        def test_ykman_program_otp_slot_2_options(self):
            output = ykman_cli(
                'otp', 'yubiotp', '2', '--public-id', 'vvccccfiluij',
                '--private-id', '267e0a88949b',
                '--key', 'b8e31ab90bb8830e3c1fe1b483a8e0d4', '-f')
            self.assertEqual('', output)
            self._check_slot_2_programmed()

        def test_ykman_program_otp_slot_2_generated_all(self):
            output = ykman_cli(
                'otp', 'yubiotp', '2', '-f', '--serial-public-id',
                '--generate-private-id', '--generate-key')
            self.assertIn('Using YubiKey serial as public ID', output)
            self.assertIn('Using a randomly generated private ID', output)
            self.assertIn('Using a randomly generated secret key', output)
            self._check_slot_2_programmed()

        def test_ykman_program_otp_slot_2_serial_public_id(self):
            output = ykman_cli(
                'otp', 'yubiotp', '2', '--serial-public-id',
                '--private-id', '267e0a88949b',
                '--key', 'b8e31ab90bb8830e3c1fe1b483a8e0d4', '-f')
            self.assertIn('Using YubiKey serial as public ID', output)
            self.assertNotIn('generated private ID', output)
            self.assertNotIn('generated secret key', output)
            self._check_slot_2_programmed()

        def test_invalid_public_id(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'yubiotp', '-P', 'imnotmodhex!')

        def test_ykman_program_otp_slot_2_generated_private_id(self):
            output = ykman_cli(
                'otp', 'yubiotp', '2', '--public-id', 'vvccccfiluij',
                '--generate-private-id',
                '--key', 'b8e31ab90bb8830e3c1fe1b483a8e0d4', '-f')
            self.assertNotIn('serial as public ID', output)
            self.assertIn('Using a randomly generated private ID', output)
            self.assertNotIn('generated secret key', output)
            self._check_slot_2_programmed()

        def test_ykman_program_otp_slot_2_generated_secret_key(self):
            output = ykman_cli(
                'otp', 'yubiotp', '2', '--public-id', 'vvccccfiluij',
                '--private-id', '267e0a88949b', '--generate-key', '-f')
            self.assertNotIn('serial as public ID', output)
            self.assertNotIn('generated private ID', output)
            self.assertIn('Using a randomly generated secret key', output)
            self._check_slot_2_programmed()

        def test_ykman_program_otp_slot_2_serial_id_conflicts_public_id(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'yubiotp', '2', '-f', '--serial-public-id',
                          '--public-id', 'vvccccfiluij',
                          '--generate-private-id', '--generate-key')
            self._check_slot_2_not_programmed()

        def test_ykman_program_otp_slot_2_generate_id_conflicts_private_id(self):  # noqa: E501
            with self.assertRaises(SystemExit):
                ykman_cli(
                    'otp', 'yubiotp', '2', '-f', '--serial-public-id',
                    '--generate-private-id', '--private-id', '267e0a88949b',
                    '--generate-key')
            self._check_slot_2_not_programmed()

        def test_ykman_program_otp_slot_2_generate_key_conflicts_key(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'yubiotp', '2', '-f', '--serial-public-id',
                          '--generate-private-id',
                          '--generate-key',
                          '--key', 'b8e31ab90bb8830e3c1fe1b483a8e0d4')
            self._check_slot_2_not_programmed()

        def test_ykman_program_chalresp_slot_2(self):
            ykman_cli('otp', 'chalresp', '2', 'abba', '-f')
            self._check_slot_2_programmed()
            ykman_cli('otp', 'chalresp', '2', '--totp', 'abba', '-f')
            self._check_slot_2_programmed()
            ykman_cli('otp', 'chalresp', '2', '--touch', 'abba', '-f')
            self._check_slot_2_programmed()

        def test_ykman_program_chalresp_slot_2_force_fails_without_key(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'chalresp', '2', '-f')
            self._check_slot_2_not_programmed()

        def test_ykman_program_chalresp_slot_2_generated(self):
            output = ykman_cli('otp', 'chalresp', '2', '-f', '-g')
            self.assertRegex(output,
                             'Using a randomly generated key: [0-9a-f]{40}$')
            self._check_slot_2_programmed()

        def test_ykman_program_chalresp_slot_2_generated_fails_if_also_given(self):  # noqa: E501
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'chalresp', '2', '-f', '-g', 'abababab')

        def test_ykman_program_chalresp_slot_2_prompt(self):
            ykman_cli('otp', 'chalresp', '2', input='abba\ny\n')
            self._check_slot_2_programmed()

        def test_ykman_program_hotp_slot_2(self):
            ykman_cli(
                'otp', 'hotp', '2',
                '27KIZZE3SD7GE2FVJJBAXEI3I6RRTPGM', '-f')
            self._check_slot_2_programmed()

        def test_ykman_program_hotp_slot_2_prompt(self):
            ykman_cli('otp', 'hotp', '2', input='abba\ny\n')
            self._check_slot_2_programmed()

        def test_update_settings_enter_slot_2(self):
            ykman_cli('otp', 'static', '2', '-f', '-g', '-l', '20')
            output = ykman_cli('otp', 'settings', '2', '-f', '--no-enter')
            self.assertIn('Updating settings for slot', output)

        def test_delete_slot_2(self):
            ykman_cli('otp', 'static', '2', '-f', '-g', '-l', '20')
            output = ykman_cli('otp', 'delete', '2', '-f')
            self.assertIn('Deleting the configuration', output)
            status = ykman_cli('otp', 'info')
            self.assertIn('Slot 2: empty', status)

        def test_access_code_slot_2(self):
            ykman_cli(
                'otp', '--access-code', '111111111111', 'static', '2',
                '--generate', '--length', '10')
            self._check_slot_2_programmed()
            self._check_slot_2_has_access_code()
            ykman_cli('otp', '--access-code', '111111111111',
                      'delete', '2', '-f')
            status = ykman_cli('otp', 'info')
            self.assertIn('Slot 2: empty', status)

        @yubikey_conditions.version_in_range((4, 3, 2), (4, 3, 5))
        def test_update_access_code_fails_on_yk_432_to_435(self):
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            self._check_slot_2_programmed()

            with self.assertRaises(SystemExit):
                ykman_cli(
                    'otp', 'settings', '--new-access-code', '111111111111',
                    '2', '-f')

            ykman_cli(
                'otp', '--access-code', '111111111111', 'static', '2', '-f',
                '--generate', '--length', '10')

            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'delete', '2', '-f')

            with self.assertRaises(SystemExit):
                ykman_cli(
                    'otp', '--access-code', '111111111111', 'settings',
                    '--new-access-code', '222222222222', '2', '-f')

            ykman_cli('otp', '--access-code', '111111111111',
                      'delete', '2', '-f')

        @yubikey_conditions.version_in_range((4, 3, 2), (4, 3, 5))
        def test_delete_access_code_fails_on_yk_432_to_435(self):
            ykman_cli('otp', '--access-code', '111111111111', 'static', '2',
                      '--generate', '--length', '10')

            self._check_slot_2_programmed()

            with self.assertRaises(SystemExit):
                ykman_cli('otp', '--access-code', '111111111111', 'settings',
                          '--delete-access-code', '2', '-f')

            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'delete', '2', '-f')

            ykman_cli('otp', '--access-code', '111111111111',
                      'delete', '2', '-f')

        @yubikey_conditions.version_not_in_range((4, 3, 2), (4, 3, 5))
        def test_update_access_code_slot_2(self):
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            self._check_slot_2_programmed()
            self._check_slot_2_does_not_have_access_code()

            ykman_cli('otp', 'settings', '--new-access-code', '111111111111',
                      '2', '-f')
            self._check_slot_2_has_access_code()

            ykman_cli('otp', '--access-code', '111111111111', 'settings',
                      '--delete-access-code', '2', '-f')
            self._check_slot_2_does_not_have_access_code()

            ykman_cli('otp', 'delete', '2', '-f')

        @yubikey_conditions.version_not_in_range((4, 3, 2), (4, 3, 5))
        def test_update_access_code_prompt_slot_2(self):
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            self._check_slot_2_programmed()
            self._check_slot_2_does_not_have_access_code()

            ykman_cli('otp', 'settings', '--new-access-code', '', '2',
                      '-f', input='111111111111')
            self._check_slot_2_has_access_code()

            ykman_cli('otp', '--access-code', '', 'settings',
                      '--delete-access-code', '2', '-f', input='111111111111')
            self._check_slot_2_does_not_have_access_code()

            ykman_cli('otp', 'delete', '2', '-f')

        @yubikey_conditions.version_not_in_range((4, 3, 2), (4, 3, 5))
        def test_new_access_code_conflicts_with_delete_access_code(self):
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            self._check_slot_2_programmed()
            self._check_slot_2_does_not_have_access_code()

            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'settings', '--delete-access-code',
                          '--new-access-code', '111111111111', '2', '-f')
            self._check_slot_2_does_not_have_access_code()

            ykman_cli('otp', 'settings', '--new-access-code', '111111111111',
                      '2', '-f')

            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'settings', '--delete-access-code',
                          '--new-access-code', '111111111111', '2', '-f')
            self._check_slot_2_has_access_code()

            ykman_cli('otp', '--access-code', '111111111111',
                      'delete', '2', '-f')

        def _check_slot_2_programmed(self):
            status = ykman_cli('otp', 'info')
            self.assertIn('Slot 2: programmed', status)

        def _check_slot_2_not_programmed(self):
            status = ykman_cli('otp', 'info')
            self.assertIn('Slot 2: empty', status)

        def _check_slot_2_has_access_code(self):
            with self.assertRaises(SystemExit):
                ykman_cli('otp', 'settings', '--pacing', '0', '2', '-f')

            ykman_cli('otp', '--access-code', '111111111111', 'settings',
                      '--pacing', '0', '2', '-f')

        def _check_slot_2_does_not_have_access_code(self):
            ykman_cli('otp', 'settings', '--pacing', '0', '2', '-f')

    class TestSlotCalculate(unittest.TestCase):

        def test_calculate_hex(self):
            ykman_cli('otp', 'delete', '2', '-f')
            ykman_cli('otp', 'chalresp', '2', 'abba', '-f')
            output = ykman_cli('otp', 'calculate', '2', 'abba')
            self.assertIn('f8de2586056d89d8b961a072d1245a495d2155e1', output)

        def test_calculate_totp(self):
            ykman_cli('otp', 'delete', '2', '-f')
            ykman_cli('otp', 'chalresp', '2', 'abba', '-f')
            output = ykman_cli('otp', 'calculate', '2', '999', '-T')
            self.assertEqual('533486', output.strip())
            output = ykman_cli('otp', 'calculate', '2', '999', '-T', '-d', '8')
            self.assertEqual('04533486', output.strip())
            output = ykman_cli('otp', 'calculate', '2', '-T')
            self.assertEqual(6, len(output.strip()))
            output = ykman_cli('otp', 'calculate', '2', '-T', '-d', '8')
            self.assertEqual(8, len(output.strip()))

    @yubikey_conditions.is_fips
    class TestFipsMode(unittest.TestCase):

        def tearDown(self):
            ykman_cli('otp', '--access-code', '111111111111',
                      'delete', '1', '-f')
            ykman_cli('otp', '--access-code', '111111111111',
                      'delete', '2', '-f')

        def test_not_fips_mode_if_no_slot_programmed(self):
            ykman_cli('otp', 'delete', '1', '-f')
            ykman_cli('otp', 'delete', '2', '-f')

            info = ykman_cli('otp', 'info')
            self.assertIn('FIPS Approved Mode: No', info)

        def test_not_fips_mode_if_slot_1_not_programmed(self):
            ykman_cli('otp', 'delete', '1', '-f')
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            info = ykman_cli('otp', 'info')
            self.assertIn('FIPS Approved Mode: No', info)

        def test_not_fips_mode_if_slot_2_not_programmed(self):
            ykman_cli('otp', 'static', '1', '--generate', '--length', '10')
            ykman_cli('otp', 'delete', '2', '-f')

            info = ykman_cli('otp', 'info')
            self.assertIn('FIPS Approved Mode: No', info)

        def test_not_fips_mode_if_no_slot_has_access_code(self):
            ykman_cli('otp', 'static', '1', '--generate', '--length', '10')
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            info = ykman_cli('otp', 'info')
            self.assertIn('FIPS Approved Mode: No', info)

        def test_not_fips_mode_if_only_slot_1_has_access_code(self):
            ykman_cli('otp', 'static', '1', '--generate', '--length', '10')
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            ykman_cli('otp', 'settings', '--new-access-code', '111111111111',
                      '1', '-f')

            info = ykman_cli('otp', 'info')
            self.assertIn('FIPS Approved Mode: No', info)

        def test_not_fips_mode_if_only_slot_2_has_access_code(self):
            ykman_cli('otp', 'static', '1', '--generate', '--length', '10')
            ykman_cli('otp', 'static', '2', '--generate', '--length', '10')

            ykman_cli('otp', 'settings', '--new-access-code', '111111111111',
                      '2', '-f')

            info = ykman_cli('otp', 'info')
            self.assertIn('FIPS Approved Mode: No', info)

        def test_fips_mode_if_both_slots_have_access_code(self):
            ykman_cli('otp', 'static', '--generate', '--length', '10',
                      '1', '-f')
            ykman_cli('otp', 'static', '--generate', '--length', '10',
                      '2', '-f')

            ykman_cli('otp', 'settings', '--new-access-code', '111111111111',
                      '1', '-f')
            ykman_cli('otp', 'settings', '--new-access-code', '111111111111',
                      '2', '-f')

            info = ykman_cli('otp', 'info')
            self.assertIn('FIPS Approved Mode: Yes', info)

    return [
        TestSlotStatus,
        TestSlotStaticPassword,
        TestSlotProgramming,
        TestSlotCalculate,
        TestFipsMode,
    ]
