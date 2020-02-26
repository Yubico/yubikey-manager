import unittest
from test.util import ykman_cli


class TestExternalLibraries(unittest.TestCase):

    def test_ykman_version(self):
        output = ykman_cli('-v')
        # Test that major version is 1 on all libs
        self.assertIn('libykpers 1', output)
        self.assertIn('libusb 1', output)

    def test_ykman_version_not_found(self):
        output = ykman_cli('-v')
        self.assertNotIn('not found!', output)
        self.assertNotIn('<pyusb backend missing>', output)
