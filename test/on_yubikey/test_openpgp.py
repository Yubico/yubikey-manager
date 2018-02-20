import unittest
from ykman.util import TRANSPORT
from .util import (DestructiveYubikeyTestCase, missing_mode, ykman_cli)


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class TestOpenPGP(DestructiveYubikeyTestCase):

    def test_openpgp_info(self):
        output = ykman_cli('openpgp', 'info')
        self.assertIn('OpenPGP version:', output)

    def test_openpgp_reset(self):
        output = ykman_cli('openpgp', 'reset', '-f')
        self.assertIn(
            'Success! All data has been cleared and default PINs are set.',
            output)
