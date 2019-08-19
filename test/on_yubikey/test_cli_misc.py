import unittest

from .framework import cli_test_suite, yubikey_conditions


@cli_test_suite
def additional_tests(ykman_cli):
    class TestYkmanInfo(unittest.TestCase):

        def test_ykman_info(self):
            info = ykman_cli('info')
            self.assertIn('Device type:', info)
            self.assertIn('Serial number:', info)
            self.assertIn('Firmware version:', info)

        @yubikey_conditions.is_not_fips
        def test_ykman_info_does_not_report_fips_for_non_fips_device(self):
            info = ykman_cli('info', '--check-fips')
            self.assertNotIn('FIPS', info)

        @yubikey_conditions.is_fips
        def test_ykman_info_reports_fips_status(self):
            info = ykman_cli('info', '--check-fips')
            self.assertIn('FIPS Approved Mode:', info)
            self.assertIn('  FIDO U2F:', info)
            self.assertIn('  OATH:', info)
            self.assertIn('  OTP:', info)

    return [TestYkmanInfo]
