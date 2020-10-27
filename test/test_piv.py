#  vim: set fileencoding=utf-8 :

import ykman.piv as piv
import unittest

from yubikit.core import NotSupportedError
from yubikit.piv import KEY_TYPE, PIN_POLICY, TOUCH_POLICY, check_key_support


class TestPivFunctions(unittest.TestCase):
    def test_generate_random_management_key(self):
        output1 = piv.generate_random_management_key()
        output2 = piv.generate_random_management_key()
        self.assertIsInstance(output1, bytes)
        self.assertIsInstance(output2, bytes)
        self.assertNotEqual(output1, output2)

    def test_supported_algorithms(self):
        with self.assertRaises(NotSupportedError):
            check_key_support(
                (3, 1, 1), KEY_TYPE.ECCP384, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )

        with self.assertRaises(NotSupportedError):
            check_key_support(
                (4, 4, 1), KEY_TYPE.RSA1024, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.RSA2048):
            with self.assertRaises(NotSupportedError):
                check_key_support(
                    (4, 3, 4), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in KEY_TYPE:
            check_key_support(
                (5, 1, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )
