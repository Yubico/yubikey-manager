import unittest
from .framework import cli_test_suite


@cli_test_suite
def additional_tests(ykman_cli):
    class TestOpenPGP(unittest.TestCase):

        def setUp(self):
            ykman_cli('openpgp', 'reset', '-f')

        def test_openpgp_info(self):
            output = ykman_cli('openpgp', 'info')
            self.assertIn('OpenPGP version:', output)

        def test_openpgp_reset(self):
            output = ykman_cli('openpgp', 'reset', '-f')
            self.assertIn(
                'Success! All data has been cleared and default PINs are set.',
                output)

    return [TestOpenPGP]
