import unittest

from .util import (DestructiveYubikeyTestCase, is_fips, ykman_cli)


class TestYkmanInfo(DestructiveYubikeyTestCase):

    def test_ykman_info(self):
        info = ykman_cli('info')
        self.assertIn('Device type:', info)
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info)

    @unittest.skipIf(not is_fips(), 'FIPS YubiKey required.')
    def test_ykman_info_reports_fips_device(self):
        info = ykman_cli('info')
        self.assertIn('This YubiKey is capable of FIPS mode.', info)

    @unittest.skipIf(is_fips(), 'Not applicable to FIPS YubiKey.')
    def test_ykman_info_does_not_report_fips_for_non_fips_device(self):
        info = ykman_cli('info')
        self.assertNotIn('FIPS', info)

    @unittest.skipIf(not is_fips(), 'FIPS YubiKey required.')
    def test_ykman_info_reports_fips_status(self):
        info = ykman_cli('info')
        self.assertIn('FIPS mode active:', info)
        self.assertIn('  - FIDO U2F:', info)
        self.assertIn('  - OATH:', info)
        self.assertIn('  - OTP:', info)
