from ykman.util import TRANSPORT
from ...util import open_file
from ..util import cli_test_suite, is_fips, DestructiveYubikeyTestCase


@cli_test_suite(TRANSPORT.CCID)
def additional_tests(ykman_cli):
    class TestFIPS(DestructiveYubikeyTestCase):

        @classmethod
        def setUpClass(cls):
            ykman_cli('piv', 'reset', '-f')

        @classmethod
        def tearDownClass(cls):
            ykman_cli('piv', 'reset', '-f')

        @is_fips
        def test_rsa1024_generate_blocked(self):
            with self.assertRaises(SystemExit):
                ykman_cli('piv', 'generate-key', '9a', '-a', 'RSA1024', '-')

        @is_fips
        def test_rsa1024_import_blocked(self):
            with self.assertRaises(SystemExit):
                with open_file('rsa_1024_key.pem') as f:
                    ykman_cli('piv', 'import-key', '9a', f.name)

    return [TestFIPS]
