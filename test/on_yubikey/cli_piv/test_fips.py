import unittest

from ...util import open_file
from ..framework import cli_test_suite, yubikey_conditions


@cli_test_suite
def additional_tests(ykman_cli):
    class TestFIPS(unittest.TestCase):

        @classmethod
        def setUpClass(cls):
            ykman_cli('piv', 'reset', '-f')

        @classmethod
        def tearDownClass(cls):
            ykman_cli('piv', 'reset', '-f')

        @yubikey_conditions.is_fips
        def test_rsa1024_generate_blocked(self):
            with self.assertRaises(SystemExit):
                ykman_cli('piv', 'generate-key', '9a', '-a', 'RSA1024', '-')

        @yubikey_conditions.is_fips
        def test_rsa1024_import_blocked(self):
            with self.assertRaises(SystemExit):
                with open_file('rsa_1024_key.pem') as f:
                    ykman_cli('piv', 'import-key', '9a', f.name)

    return [TestFIPS]
