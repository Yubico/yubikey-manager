import unittest
from ykman.util import TRANSPORT
from ..util import (DestructiveYubikeyTestCase, missing_mode, ykman_cli)


DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_PUK = '12345678'
NON_DEFAULT_PUK = '87654321'
DEFAULT_MANAGEMENT_KEY = '010203040506070801020304050607080102030405060708'
NON_DEFAULT_MANAGEMENT_KEY = '010103040506070801020304050607080102030405060708'


def old_new_new(old, new):
    return '{0}\n{1}\n{1}\n'.format(old, new)


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class PivTestCase(DestructiveYubikeyTestCase):
    pass


class Misc(PivTestCase):

    def test_info(self):
        output = ykman_cli('piv', 'info')
        self.assertIn('PIV version:', output)

    def test_reset(self):
        output = ykman_cli('piv', 'reset', '-f')
        self.assertIn('Success!', output)
