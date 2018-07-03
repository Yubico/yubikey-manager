import unittest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ykman.util import (Cve201715361VulnerableError)
from ..util import (
    is_NEO, no_attestation, skip_not_roca, skip_roca, ykman_cli, is_fips)
from .util import (PivTestCase, DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY)


class KeyManagement(PivTestCase):

    @classmethod
    def setUpClass(cls):
        ykman_cli('piv', 'reset', '-f')

    @classmethod
    def tearDownClass(cls):
        ykman_cli('piv', 'reset', '-f')

    @unittest.skipIf(*skip_roca)
    def test_generate_key_default(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-m', DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(*skip_not_roca)
    def test_generate_key_default_cve201715361(self):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    @unittest.skipIf(*skip_roca)
    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_key_rsa1024(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(*skip_roca)
    def test_generate_key_rsa2048(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA2048',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    @unittest.skipIf(*skip_not_roca)
    def test_generate_key_rsa1024_cve201715361(self):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
                DEFAULT_MANAGEMENT_KEY, '-')

    @unittest.skipIf(*skip_not_roca)
    def test_generate_key_rsa2048_cve201715361(self):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA2048',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    def test_generate_key_eccp256(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(is_NEO(), 'ECCP384 not available.')
    def test_generate_key_eccp384(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP384', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(is_NEO(), 'Pin policy not available.')
    def test_generate_key_pin_policy_always(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--pin-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(is_NEO(), 'Touch policy not available.')
    def test_generate_key_touch_policy_always(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--touch-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(*no_attestation)
    def test_attest_key(self):
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        output = ykman_cli('piv', 'attest', '9a', '-')
        self.assertIn('BEGIN CERTIFICATE', output)

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr(self):
        for algo in ('ECCP256', 'RSA1024'):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', algo, '-m',
                DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
            output = ykman_cli(
                'piv', 'generate-csr', '9a', '/tmp/test-pub-key.pem',
                '-s', 'test-subject', '-P', DEFAULT_PIN, '-')
            csr = x509.load_pem_x509_csr(output.encode(), default_backend())
            self.assertTrue(csr.is_signature_valid)

    @unittest.skipIf(*no_attestation)
    def test_export_attestation_certificate(self):
        output = ykman_cli('piv', 'export-certificate', 'f9', '-')
        self.assertIn('BEGIN CERTIFICATE', output)
