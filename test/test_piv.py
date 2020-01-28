#  vim: set fileencoding=utf-8 :

import ykman.piv as piv

from ykman.piv import ALGO


class FakeController(object):
    def __init__(self, version):
        self.version = version

    @property
    def is_fips(self):
        return piv.PivController.is_fips.fget(self)


class TestPivFunctions(object):

    def test_generate_random_management_key(self):
        output1 = piv.generate_random_management_key()
        output2 = piv.generate_random_management_key()
        assert isinstance(output1, bytes)
        assert isinstance(output2, bytes)
        assert output1 != output2

    def test_supported_algorithms(self):
        neo_supported = piv.PivController.supported_algorithms.fget(
            FakeController((3, 1, 1)))
        assert ALGO.TDES not in neo_supported
        assert ALGO.ECCP384 not in neo_supported

        fips_supported = piv.PivController.supported_algorithms.fget(
            FakeController((4, 4, 1)))
        assert ALGO.TDES not in fips_supported
        assert ALGO.RSA1024 not in fips_supported

        roca_supported = piv.PivController.supported_algorithms.fget(
            FakeController((4, 3, 4)))
        assert ALGO.TDES not in roca_supported
        assert ALGO.RSA1024 not in roca_supported
        assert ALGO.RSA2048 not in roca_supported

        yk5_supported = piv.PivController.supported_algorithms.fget(
            FakeController((5, 1, 0)))
        assert set(yk5_supported) == set([a for a in ALGO if a != ALGO.TDES])
