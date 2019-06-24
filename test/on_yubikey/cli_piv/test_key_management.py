from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ykman.util import (Cve201715361VulnerableError)
from ..util import (
    yubikey_any_ccid, yubikey_each_ccid, fips, neo, piv_attestation, roca)
from .util import (PivTestCase, DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY)


class KeyManagement(PivTestCase):

    @classmethod
    @yubikey_each_ccid()
    def setUpClass(cls, ykman_cli):
        ykman_cli('piv', 'reset', '-f')

    @classmethod
    @yubikey_each_ccid()
    def tearDownClass(cls, ykman_cli):
        ykman_cli('piv', 'reset', '-f')

    @yubikey_any_ccid(roca(False))
    def test_generate_key_default(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-m', DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @yubikey_any_ccid(roca(True))
    def test_generate_key_default_cve201715361(self, ykman_cli):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    @yubikey_any_ccid(roca(False), fips(False))
    def test_generate_key_rsa1024(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @yubikey_any_ccid(roca(False))
    def test_generate_key_rsa2048(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA2048',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @yubikey_any_ccid(fips(False), roca(True))
    def test_generate_key_rsa1024_cve201715361(self, ykman_cli):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
                DEFAULT_MANAGEMENT_KEY, '-')

    @yubikey_any_ccid(roca(True))
    def test_generate_key_rsa2048_cve201715361(self, ykman_cli):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA2048',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    @yubikey_each_ccid()
    def test_generate_key_eccp256(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @yubikey_each_ccid(neo(False))
    def test_generate_key_eccp384(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP384', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @yubikey_each_ccid(neo(False))
    def test_generate_key_pin_policy_always(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--pin-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @yubikey_each_ccid(neo(False))
    def test_generate_key_touch_policy_always(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--touch-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @yubikey_each_ccid(piv_attestation(True))
    def test_attest_key(self, ykman_cli):
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        output = ykman_cli('piv', 'attest', '9a', '-')
        self.assertIn('BEGIN CERTIFICATE', output)

    def _test_generate_csr(self, ykman_cli, algo):
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', algo, '-m',
            DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
        output = ykman_cli(
            'piv', 'generate-csr', '9a', '/tmp/test-pub-key.pem',
            '-s', 'test-subject', '-P', DEFAULT_PIN, '-')
        csr = x509.load_pem_x509_csr(output.encode(), default_backend())
        self.assertTrue(csr.is_signature_valid)

    @yubikey_each_ccid(fips(False), roca(False))
    def test_generate_csr_rsa1024(self, ykman_cli):
        self._test_generate_csr(ykman_cli, 'RSA1024')

    @yubikey_each_ccid()
    def test_generate_csr_eccp256(self, ykman_cli):
        self._test_generate_csr(ykman_cli, 'ECCP256')

    @yubikey_each_ccid()
    def test_import_verify_correct_cert_succeeds_with_pin(self, ykman_cli):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '--pin-policy', 'ALWAYS', '-')

        ykman_cli(
            'piv', 'generate-certificate', '9a', '-',
            '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN, '-s', 'test',
            input=public_key_pem)

        ykman_cli('piv', 'export-certificate', '9a', '/tmp/test-pub-key.pem')

        with self.assertRaises(SystemExit):
            ykman_cli(
                'piv', 'import-certificate', '--verify',
                '9a', '/tmp/test-pub-key.pem',
                '-m', DEFAULT_MANAGEMENT_KEY)

        ykman_cli(
            'piv', 'import-certificate', '--verify',
            '9a', '/tmp/test-pub-key.pem',
            '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN)
        ykman_cli(
            'piv', 'import-certificate', '--verify',
            '9a', '/tmp/test-pub-key.pem',
            '-m', DEFAULT_MANAGEMENT_KEY, input=DEFAULT_PIN)

    @yubikey_each_ccid()
    def test_import_verify_wrong_cert_fails(self, ykman_cli):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '--pin-policy', 'ALWAYS', '-')

        ykman_cli(
            'piv', 'generate-certificate', '9a', '-',
            '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN, '-s', 'test',
            input=public_key_pem)

        cert_pem = ykman_cli('piv', 'export-certificate', '9a', '-')

        # Overwrite the key with a new one
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '--pin-policy', 'ALWAYS', '-',
            input=public_key_pem)

        with self.assertRaises(SystemExit):
            ykman_cli(
                'piv', 'import-certificate', '--verify', '9a', '-',
                '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN, input=cert_pem)

    @yubikey_each_ccid()
    def test_import_no_verify_wrong_cert_succeeds(self, ykman_cli):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '--pin-policy', 'ALWAYS', '-')

        ykman_cli(
            'piv', 'generate-certificate', '9a', '-',
            '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN, '-s', 'test',
            input=public_key_pem)

        cert_pem = ykman_cli('piv', 'export-certificate', '9a', '-')

        # Overwrite the key with a new one
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '--pin-policy', 'ALWAYS', '-',
            input=public_key_pem)

        with self.assertRaises(SystemExit):
            ykman_cli(
                'piv', 'import-certificate', '--verify', '9a', '-',
                '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN, input=cert_pem)

        ykman_cli(
            'piv', 'import-certificate', '9a', '-',
            '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN,
            input=cert_pem)

    @yubikey_each_ccid(piv_attestation(True))
    def test_export_attestation_certificate(self, ykman_cli):
        output = ykman_cli('piv', 'export-certificate', 'f9', '-')
        self.assertIn('BEGIN CERTIFICATE', output)
