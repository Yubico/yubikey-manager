#  vim: set fileencoding=utf-8 :

from ykman.piv import generate_random_management_key
import unittest

from yubikit.core import NotSupportedError
from yubikit.piv import (
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    PIN_POLICY,
    TOUCH_POLICY,
    check_key_support,
)


class TestPivFunctions(unittest.TestCase):
    def test_generate_random_management_key(self):
        output1 = generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES)
        output2 = generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES)
        self.assertIsInstance(output1, bytes)
        self.assertIsInstance(output2, bytes)
        self.assertNotEqual(output1, output2)

        self.assertEqual(
            24, len(generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES))
        )
        self.assertEqual(
            16, len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES128))
        )
        self.assertEqual(
            24, len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES192))
        )
        self.assertEqual(
            32, len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES256))
        )

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
