import unittest
from ykman.util import TRANSPORT
from ..util import (DestructiveYubikeyTestCase, missing_mode)


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
