import unittest

from ..framework import cli_test_suite


@cli_test_suite
def additional_tests(ykman_cli):
    class Misc(unittest.TestCase):

        def setUp(self):
            ykman_cli('piv', 'reset', '-f')

        def test_info(self):
            output = ykman_cli('piv', 'info')
            self.assertIn('PIV version:', output)

        def test_reset(self):
            output = ykman_cli('piv', 'reset', '-f')
            self.assertIn('Success!', output)

    return [Misc]
