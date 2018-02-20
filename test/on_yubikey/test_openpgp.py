import unittest
from ykman.util import TRANSPORT
from .util import (
    destructive_tests_not_activated, missing_mode, not_one_yubikey, ykman_cli)


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
