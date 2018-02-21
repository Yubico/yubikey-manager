import unittest
from ykman.util import TRANSPORT
from .util import (DestructiveYubikeyTestCase, missing_mode, ykman_cli)


@unittest.skipIf(*missing_mode(TRANSPORT.U2F))
class TestFidoFunctions(DestructiveYubikeyTestCase):

    def test_fido_set_pin(self):
        output = ykman_cli('fido', 'info')
        self.assertIn('PIN is not set.', output)
        ykman_cli('fido', 'set-pin', '--new-pin', '123abc')
        output = ykman_cli('fido', 'info')
        self.assertIn('PIN is set', output)
