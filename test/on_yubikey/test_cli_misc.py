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
