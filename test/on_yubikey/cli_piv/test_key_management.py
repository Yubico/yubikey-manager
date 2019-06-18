import functools
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ykman.descriptor import open_device
from ykman.util import (Cve201715361VulnerableError, TRANSPORT)
from ..util import (
    _test_serials, _ykman_cli, fips, neo, piv_attestation, roca)
from .util import (PivTestCase, DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY)


def make_test_case(dev):
    ykman_cli = functools.partial(_ykman_cli, dev.serial)

    class KeyManagement(PivTestCase):
        @classmethod
        def setUpClass(cls):
            ykman_cli('piv', 'reset', '-f')

        @classmethod
        def tearDownClass(cls):
            ykman_cli('piv', 'reset', '-f')

        @roca(False)
        def test_generate_key_default(self):
            output = ykman_cli(
                'piv', 'generate-key', '9a', '-m', DEFAULT_MANAGEMENT_KEY, '-')
            self.assertIn('BEGIN PUBLIC KEY', output)

        @roca(True)
        def test_generate_key_default_cve201715361(self):
            with self.assertRaises(Cve201715361VulnerableError):
                ykman_cli(
                    'piv', 'generate-key', '9a',
                    '-m', DEFAULT_MANAGEMENT_KEY, '-')

        @roca(False)
        @fips(False)
        def test_generate_key_rsa1024(self):
            output = ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
                DEFAULT_MANAGEMENT_KEY, '-')
            self.assertIn('BEGIN PUBLIC KEY', output)

        @roca(False)
        def test_generate_key_rsa2048(self):
            output = ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'RSA2048',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')
            self.assertIn('BEGIN PUBLIC KEY', output)

        @fips(False)
        @roca(True)
        def test_generate_key_rsa1024_cve201715361(self):
            with self.assertRaises(Cve201715361VulnerableError):
                ykman_cli(
                    'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
                    DEFAULT_MANAGEMENT_KEY, '-')

        @roca(True)
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

        @neo(False)
        def test_generate_key_eccp384(self):
            output = ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'ECCP384', '-m',
                DEFAULT_MANAGEMENT_KEY, '-')
            self.assertIn('BEGIN PUBLIC KEY', output)

        @neo(False)
        def test_generate_key_pin_policy_always(self):
            output = ykman_cli(
                'piv', 'generate-key', '9a', '--pin-policy', 'ALWAYS', '-m',
                DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
            self.assertIn('BEGIN PUBLIC KEY', output)

        @neo(False)
        def test_generate_key_touch_policy_always(self):
            output = ykman_cli(
                'piv', 'generate-key', '9a', '--touch-policy', 'ALWAYS', '-m',
                DEFAULT_MANAGEMENT_KEY, '-a', 'ECCP256', '-')
            self.assertIn('BEGIN PUBLIC KEY', output)

        @piv_attestation(True)
        def test_attest_key(self):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', 'ECCP256',
                '-m', DEFAULT_MANAGEMENT_KEY, '-')
            output = ykman_cli('piv', 'attest', '9a', '-')
            self.assertIn('BEGIN CERTIFICATE', output)

        def _test_generate_csr(self, algo):
            ykman_cli(
                'piv', 'generate-key', '9a', '-a', algo, '-m',
                DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
            output = ykman_cli(
                'piv', 'generate-csr', '9a', '/tmp/test-pub-key.pem',
                '-s', 'test-subject', '-P', DEFAULT_PIN, '-')
            csr = x509.load_pem_x509_csr(output.encode(), default_backend())
            self.assertTrue(csr.is_signature_valid)

        @fips(False)
        @roca(False)
        def test_generate_csr_rsa1024(self):
            self._test_generate_csr('RSA1024')

        def test_generate_csr_eccp256(self):
            self._test_generate_csr('ECCP256')

        def test_import_verify_correct_cert_succeeds_with_pin(self):
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

        def test_import_verify_wrong_cert_fails(self):
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
                    '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN,
                    input=cert_pem)

        def test_import_no_verify_wrong_cert_succeeds(self):
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
                    '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN,
                    input=cert_pem)

            ykman_cli(
                'piv', 'import-certificate', '9a', '-',
                '-m', DEFAULT_MANAGEMENT_KEY, '-P', DEFAULT_PIN,
                input=cert_pem)

        @piv_attestation(True)
        def test_export_attestation_certificate(self):
            output = ykman_cli('piv', 'export-certificate', 'f9', '-')
            self.assertIn('BEGIN CERTIFICATE', output)

    fw_version = '.'.join(str(v) for v in dev.version)
    KeyManagement.__qualname__ = f'KeyManagement_{fw_version}_{dev.serial}'

    for attr_name in dir(KeyManagement):
        method = getattr(KeyManagement, attr_name)
        if attr_name.startswith('test') and 'yubikey_conditions' in dir(method):
            conditions = getattr(method, 'yubikey_conditions')
            if not all(cond(dev) for cond in conditions):
                delattr(KeyManagement, attr_name)

    return KeyManagement


def additional_tests():
    suite = unittest.TestSuite()

    for serial in _test_serials:
        with open_device(transports=TRANSPORT.CCID, serial=serial) as dev:
            test_case = make_test_case(dev)
            for attr_name in dir(test_case):
                if attr_name.startswith('test'):
                    suite.addTest(test_case(attr_name))

    return suite
