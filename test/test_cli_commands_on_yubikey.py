from __future__ import print_function
import unittest
import time
from .on_yubikey.util import (
    destructive_tests_not_activated, not_one_yubikey, ykman_cli)


@unittest.skipIf(*destructive_tests_not_activated)
@unittest.skipIf(*not_one_yubikey)
class TestYkmanInfo(unittest.TestCase):

    def test_ykman_info(self):
        time.sleep(3)
        info = ykman_cli('info')
        self.assertIn('Device type:', info)
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info)
