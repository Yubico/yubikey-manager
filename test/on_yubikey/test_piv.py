import unittest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from ykman.util import (TRANSPORT, Cve201715361VulnerableError)
from .util import (
    DestructiveYubikeyTestCase, is_NEO, missing_mode, no_attestation,
    skip_not_roca, skip_roca, ykman_cli)


DEFAULT_MANAGEMENT_KEY = '010203040506070801020304050607080102030405060708'
NON_DEFAULT_MANAGEMENT_KEY = '010103040506070801020304050607080102030405060708'


def _verify_cert(cert, pubkey):
    cert_signature = cert.signature
    cert_bytes = cert.tbs_certificate_bytes

    if isinstance(pubkey, rsa.RSAPublicKey):
        pubkey.verify(cert_signature, cert_bytes, padding.PKCS1v15(),
                      cert.signature_hash_algorithm)
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        pubkey.verify(cert_signature, cert_bytes,
                      ec.ECDSA(cert.signature_hash_algorithm))
    else:
        raise ValueError('Unsupported public key value')


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class TestPIV(DestructiveYubikeyTestCase):

    def test_piv_info(self):
        output = ykman_cli('piv', 'info')
        self.assertIn('PIV version:', output)

    def test_piv_reset(self):
        output = ykman_cli('piv', 'reset', '-f')
        self.assertIn('Success!', output)

    @unittest.skipIf(*skip_roca)
    def test_piv_generate_key_default(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-m', DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(*skip_not_roca)
    def test_piv_generate_key_default_cve201715361(self):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    @unittest.skipIf(*skip_roca)
    def test_piv_generate_key_rsa1024(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(*skip_roca)
    def test_piv_generate_key_rsa2048(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA2048',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(*skip_not_roca)
    def test_piv_generate_key_rsa1024_cve201715361(self):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
                DEFAULT_MANAGEMENT_KEY, '-')

    @unittest.skipIf(*skip_not_roca)
    def test_piv_generate_key_rsa2048_cve201715361(self):
        with self.assertRaises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA2048',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    def test_piv_generate_key_eccp256(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(is_NEO(), 'ECCP384 not available.')
    def test_piv_generate_key_eccp384(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP384', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(is_NEO(), 'Pin policy not available.')
    def test_piv_generate_key_pin_policy_always(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--pin-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(is_NEO(), 'Touch policy not available.')
    def test_piv_generate_key_touch_policy_always(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--touch-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(*no_attestation)
    def test_piv_attest_key(self):
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        output = ykman_cli('piv', 'attest', '9a', '-')
        self.assertIn('BEGIN CERTIFICATE', output)

    def test_piv_generate_self_signed(self):
        for algo in ('ECCP256', 'RSA1024'):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', algo, '-m',
                DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
            ykman_cli(
                'piv', 'generate-certificate', '9a', '-m',
                DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem',
                '-s', 'subject-' + algo, '-P', '123456')
            output = ykman_cli('piv', 'export-certificate', '9a', '-')
            cert = x509.load_pem_x509_certificate(output.encode(),
                                                  default_backend())
            _verify_cert(cert, cert.public_key())

            output = ykman_cli('piv', 'info')
            self.assertIn('subject-' + algo, output)

    def test_piv_generate_csr(self):
        for algo in ('ECCP256', 'RSA1024'):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', algo, '-m',
                DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
            output = ykman_cli(
                'piv', 'generate-csr', '9a', '/tmp/test-pub-key.pem',
                '-s', 'test-subject', '-P', '123456', '-')
            csr = x509.load_pem_x509_csr(output.encode(), default_backend())
            self.assertTrue(csr.is_signature_valid)

    @unittest.skipIf(*no_attestation)
    def test_piv_export_attestation_certificate(self):
        output = ykman_cli('piv', 'export-certificate', 'f9', '-')
        self.assertIn('BEGIN CERTIFICATE', output)

    def test_piv_change_management_key_protect(self):
        ykman_cli(
            'piv', 'change-management-key', '-p', '-P', '123456',
            '-m', DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        self.assertIn(
            'Management key is stored on the YubiKey, protected by PIN',
            output)
        ykman_cli('piv', 'reset', '-f')  # Cleanup, should maybe be done always?

    def test_piv_change_management_key_prompt(self):
        ykman_cli('piv', 'change-management-key',
                  input=DEFAULT_MANAGEMENT_KEY + '\n' +
                  NON_DEFAULT_MANAGEMENT_KEY +
                  '\n' + NON_DEFAULT_MANAGEMENT_KEY + '\n')
        ykman_cli('piv', 'change-management-key',
                  input=NON_DEFAULT_MANAGEMENT_KEY + '\n' +
                  DEFAULT_MANAGEMENT_KEY +
                  '\n' + DEFAULT_MANAGEMENT_KEY + '\n')

    def test_piv_change_pin(self):
        ykman_cli('piv', 'change-pin', '-P', '123456', '-n', '654321')
        ykman_cli('piv', 'change-pin', '-P', '654321', '-n', '123456')

    def test_piv_change_pin_prompt(self):
        ykman_cli('piv', 'change-pin', input='123456\n654321\n654321\n')
        ykman_cli('piv', 'change-pin', input='654321\n123456\n123456\n')

    def test_piv_change_puk(self):
        o1 = ykman_cli('piv', 'change-puk', '-p', '12345678', '-n', '87654321')
        self.assertIn('New PUK set.', o1)

        o2 = ykman_cli('piv', 'change-puk', '-p', '87654321', '-n', '12345678')
        self.assertIn('New PUK set.', o2)

        with self.assertRaises(SystemExit):
            ykman_cli('piv', 'change-puk', '-p', '87654321', '-n', '12345678')

    def test_piv_change_puk_prompt(self):
        ykman_cli('piv', 'change-puk', input='12345678\n87654321\n87654321\n')
        ykman_cli('piv', 'change-puk', input='87654321\n12345678\n12345678\n')
