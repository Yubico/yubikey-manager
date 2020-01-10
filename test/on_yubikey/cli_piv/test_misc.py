import unittest

from ..framework import cli_test_suite
from .util import DEFAULT_MANAGEMENT_KEY


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

        def test_write_read_object(self):
            data = 'test data'
            for i in range(0, 3):
                ykman_cli(
                    'piv', 'write-object',
                    '-m', DEFAULT_MANAGEMENT_KEY, '0x5f0001',
                    '-', input=data)
                data = ykman_cli('piv', 'read-object', '0x5f0001')
            self.assertEqual(data, 'test data')

    return [Misc]
