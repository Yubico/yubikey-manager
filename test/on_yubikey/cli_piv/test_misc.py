import unittest

from ykman.piv import OBJ
from .util import DEFAULT_MANAGEMENT_KEY
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
            ykman_cli(
                'piv', 'write-object',
                '-m', DEFAULT_MANAGEMENT_KEY, '0x5f0001',
                '-', input='test data')
            output = ykman_cli('piv', 'read-object', '0x5f0001')
            self.assertEqual('test data\n', output)

        def test_export_invalid_certificate_fails(self):
            ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                      '-m', DEFAULT_MANAGEMENT_KEY,
                      input='Kom ihåg att du aldrig får snyta dig i mattan!')

            with self.assertRaises(SystemExit):
                ykman_cli('piv', 'export-certificate',
                          hex(OBJ.AUTHENTICATION), '-')

        def test_info_with_invalid_certificate_does_not_crash(self):
            ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                      '-m', DEFAULT_MANAGEMENT_KEY,
                      input='Kom ihåg att du aldrig får snyta dig i mattan!')
            ykman_cli('piv', 'info')

    return [Misc]
