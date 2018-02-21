import unittest
from ykman.util import TRANSPORT
from .util import (DestructiveYubikeyTestCase, missing_mode, ykman_cli)


@unittest.skipIf(*missing_mode(TRANSPORT.U2F))
class TestFidoFunctions(DestructiveYubikeyTestCase):

    def test_fido_change_pin(self):
        output = ykman_cli('--log-level', 'DEBUG', 'fido', 'info')
        self.assertIn('PIN is not set.', output)
        ykman_cli('fido', 'change-pin', '--new-pin', '123abc')
        output = ykman_cli('fido', 'info')
        self.assertIn('PIN is set', output)
