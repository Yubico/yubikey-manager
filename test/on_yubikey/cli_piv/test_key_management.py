import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ykman.util import (Cve201715361VulnerableError)
from ..framework import yubikey_conditions
from .util import (DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY)


def generate_pem_eccp256_key():
    pk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


class KeyManagement(object):

    @pytest.fixture(autouse=True, scope='class')
    def setUpTearDown(self, ykman_cli):
        ykman_cli('piv', 'reset', '-f')
        yield None
        ykman_cli('piv', 'reset', '-f')

    @yubikey_conditions.is_not_roca
    def test_generate_key_default(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-m', DEFAULT_MANAGEMENT_KEY, '-')
        assert 'BEGIN PUBLIC KEY' in output

    @yubikey_conditions.is_roca
    def test_generate_key_default_cve201715361(self, ykman_cli):
        with pytest.raises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    @yubikey_conditions.is_not_roca
    @yubikey_conditions.is_not_fips
    def test_generate_key_rsa1024(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        assert 'BEGIN PUBLIC KEY' in output

    @yubikey_conditions.is_not_roca
    def test_generate_key_rsa2048(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA2048',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        assert 'BEGIN PUBLIC KEY' in output

    @yubikey_conditions.is_not_fips
    @yubikey_conditions.is_roca
    def test_generate_key_rsa1024_cve201715361(self, ykman_cli):
        with pytest.raises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
                DEFAULT_MANAGEMENT_KEY, '-')

    @yubikey_conditions.is_roca
    def test_generate_key_rsa2048_cve201715361(self, ykman_cli):
        with pytest.raises(Cve201715361VulnerableError):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA2048',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')

    def test_generate_key_eccp256(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        assert 'BEGIN PUBLIC KEY' in output

    def test_import_key_eccp256(self, ykman_cli):
        ykman_cli(
            'piv', 'import-key', '9a',
            '-m', DEFAULT_MANAGEMENT_KEY,
            '-', input=generate_pem_eccp256_key())

    @yubikey_conditions.is_not_neo
    def test_generate_key_eccp384(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP384', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        assert 'BEGIN PUBLIC KEY' in output

    @yubikey_conditions.is_not_neo
    def test_generate_key_pin_policy_always(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--pin-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        assert 'BEGIN PUBLIC KEY' in output

    @yubikey_conditions.is_not_neo
    def test_import_key_pin_policy_always(self, ykman_cli):
        for pin_policy in ['ALWAYS', 'always']:
            ykman_cli(
                'piv', 'import-key', '9a',
                '--pin-policy', pin_policy,
                '-m', DEFAULT_MANAGEMENT_KEY,
                '-', input=generate_pem_eccp256_key())

    @yubikey_conditions.is_not_neo
    def test_generate_key_touch_policy_always(self, ykman_cli):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--touch-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
        assert 'BEGIN PUBLIC KEY' in output

    @yubikey_conditions.is_not_neo
    def test_import_key_touch_policy_always(self, ykman_cli):
        for touch_policy in ['ALWAYS', 'always']:
            ykman_cli(
                'piv', 'import-key', '9a',
                '--touch-policy', touch_policy,
                '-m', DEFAULT_MANAGEMENT_KEY,
                '-', input=generate_pem_eccp256_key())

    @yubikey_conditions.supports_piv_attestation
    def test_attest_key(self, ykman_cli):
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256',
            '-m', DEFAULT_MANAGEMENT_KEY, '-')
        output = ykman_cli('piv', 'attest', '9a', '-')
        assert 'BEGIN CERTIFICATE' in output

    def _test_generate_csr(self, ykman_cli, algo):
        ykman_cli(
            'piv', 'generate-key', '9a', '-a', algo, '-m',
            DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
        output = ykman_cli(
            'piv', 'generate-csr', '9a', '/tmp/test-pub-key.pem',
            '-s', 'test-subject', '-P', DEFAULT_PIN, '-')
        csr = x509.load_pem_x509_csr(output.encode(), default_backend())
        assert csr.is_signature_valid

    @yubikey_conditions.is_not_fips
    @yubikey_conditions.is_not_roca
    def test_generate_csr_rsa1024(self, ykman_cli):
        self._test_generate_csr(ykman_cli, 'RSA1024')

    def test_generate_csr_eccp256(self, ykman_cli):
        self._test_generate_csr(ykman_cli, 'ECCP256')

    def test_import_verify_correct_cert_succeeds_with_pin(self, ykman_cli):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '--pin-policy', 'ALWAYS', '-')

        ykman_cli(
            'piv', 'generate-certificate', '9a', '-',
            '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN, '-s', 'test',
            input=public_key_pem)

        ykman_cli('piv', 'export-certificate', '9a',
                  '/tmp/test-pub-key.pem')

        with pytest.raises(SystemExit):
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

        with pytest.raises(SystemExit):
            ykman_cli(
                'piv', 'import-certificate', '--verify', '9a', '-',
                '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN,
                input=cert_pem)

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

        with pytest.raises(SystemExit):
            ykman_cli(
                'piv', 'import-certificate', '--verify', '9a', '-',
                '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN,
                input=cert_pem)

        ykman_cli(
            'piv', 'import-certificate', '9a', '-',
            '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN,
            input=cert_pem)

    @yubikey_conditions.supports_piv_attestation
    def test_export_attestation_certificate(self, ykman_cli):
        output = ykman_cli('piv', 'export-certificate', 'f9', '-')
        assert 'BEGIN CERTIFICATE' in output
