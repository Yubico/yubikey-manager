#  vim: set fileencoding=utf-8 :

import ykman.piv as piv
import unittest

from ykman.piv import ALGO


class FakeController(object):
    def __init__(self, version):
        self.version = version

    @property
    def is_fips(self):
        return piv.PivController.is_fips.fget(self)


class TestPivFunctions(unittest.TestCase):

    def test_generate_random_management_key(self):
        output1 = piv.generate_random_management_key()
        output2 = piv.generate_random_management_key()
        self.assertIsInstance(output1, bytes)
        self.assertIsInstance(output2, bytes)
        self.assertNotEqual(output1, output2)

    def test_supported_algorithms(self):
        neo_supported = piv.PivController.supported_algorithms.fget(
            FakeController((3, 1, 1)))
        self.assertNotIn(ALGO.TDES, neo_supported)
        self.assertNotIn(ALGO.ECCP384, neo_supported)

        fips_supported = piv.PivController.supported_algorithms.fget(
            FakeController((4, 4, 1)))
        self.assertNotIn(ALGO.TDES, fips_supported)
        self.assertNotIn(ALGO.RSA1024, fips_supported)

        roca_supported = piv.PivController.supported_algorithms.fget(
            FakeController((4, 3, 4)))
        self.assertNotIn(ALGO.TDES, roca_supported)
        self.assertNotIn(ALGO.RSA1024, roca_supported)
        self.assertNotIn(ALGO.RSA2048, roca_supported)

        yk5_supported = piv.PivController.supported_algorithms.fget(
            FakeController((5, 1, 0)))
        self.assertEqual(
            set(yk5_supported),
            set([a for a in ALGO if a != ALGO.TDES]),
        )
