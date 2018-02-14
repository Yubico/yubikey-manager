#  vim: set fileencoding=utf-8 :

import ykman.piv as piv
import unittest


class TestPivFunctions(unittest.TestCase):

    def test_generate_random_management_key(self):
        output1 = piv.generate_random_management_key()
        output2 = piv.generate_random_management_key()
        self.assertIsInstance(output1, bytes)
        self.assertIsInstance(output2, bytes)
        self.assertNotEqual(output1, output2)
