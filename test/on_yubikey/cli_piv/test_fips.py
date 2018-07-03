import unittest
from ...util import open_file
from ..util import ykman_cli, is_fips
from .util import PivTestCase


@unittest.skipIf(not is_fips(), 'YubiKey FIPS required.')
class TestFIPS(PivTestCase):

    @classmethod
    def setUpClass(cls):
        ykman_cli('piv', 'reset', '-f')

    @classmethod
    def tearDownClass(cls):
        ykman_cli('piv', 'reset', '-f')

    def test_rsa1024_generate_blocked(self):
        with self.assertRaises(SystemExit):
            ykman_cli('piv', 'generate-key', '9a', '-a', 'RSA1024', '-')

    def test_rsa1024_import_blocked(self):
        with self.assertRaises(SystemExit):
            with open_file('rsa_1024_key.pem') as f:
                ykman_cli('piv', 'import-key', '9a', f.name)
