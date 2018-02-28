import re
import unittest
from binascii import b2a_hex
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from ykman.util import (TRANSPORT, Cve201715361VulnerableError)
from .util import (
    DestructiveYubikeyTestCase, is_NEO, missing_mode, no_attestation,
    skip_not_roca, skip_roca, ykman_cli)


DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_PUK = '12345678'
NON_DEFAULT_PUK = '87654321'
DEFAULT_MANAGEMENT_KEY = '010203040506070801020304050607080102030405060708'
NON_DEFAULT_MANAGEMENT_KEY = '010103040506070801020304050607080102030405060708'


def old_new_new(old, new):
    return '{0}\n{1}\n{1}\n'.format(old, new)


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
class PivTestCase(DestructiveYubikeyTestCase):
    pass


class Misc(PivTestCase):

    def test_info(self):
        output = ykman_cli('piv', 'info')
        self.assertIn('PIV version:', output)

    def test_reset(self):
        output = ykman_cli('piv', 'reset', '-f')
        self.assertIn('Success!', output)


class KeyManagement(PivTestCase):

    @classmethod
    def setUpClass(cls):
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


class GenerateSelfSigned_DefaultMgmKey(PivTestCase):

    @classmethod
    def setUpClass(cls):
        ykman_cli('piv', 'reset', '-f')

    def _test_generate_self_signed(self, slot):
        for algo in ('ECCP256', 'RSA1024'):
            ykman_cli(
                'piv', 'generate-key', slot, '-a', algo, '-m',
                DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
            ykman_cli(
                'piv', 'generate-certificate', slot, '-m',
                DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem',
                '-s', 'subject-' + algo, '-P', DEFAULT_PIN)
            output = ykman_cli('piv', 'export-certificate', slot, '-')
            cert = x509.load_pem_x509_certificate(output.encode(),
                                                  default_backend())
            _verify_cert(cert, cert.public_key())
            fingerprint = b2a_hex(cert.fingerprint(hashes.SHA256())).decode(
                'ascii')

            output = ykman_cli('piv', 'info')
            self.assertIn('Fingerprint:\t' + fingerprint, output)

    def test_generate_self_signed_slot_9a(self):
        self._test_generate_self_signed('9a')

    def test_generate_self_signed_slot_9c(self):
        self._test_generate_self_signed('9c')

    def test_generate_self_signed_slot_9d(self):
        self._test_generate_self_signed('9d')

    def test_generate_self_signed_slot_9e(self):
        self._test_generate_self_signed('9e')


class GenerateSelfSigned_ProtectedMgmKey(PivTestCase):

    @classmethod
    def setUpClass(cls):
        ykman_cli('piv', 'reset', '-f')
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                  '-m', DEFAULT_MANAGEMENT_KEY)

    def _test_generate_self_signed(self, slot):
        for algo in ('ECCP256', 'RSA1024'):
            ykman_cli(
                'piv', 'generate-key', slot, '-a', algo, '-P', DEFAULT_PIN,
                '/tmp/test-pub-key.pem')
            ykman_cli(
                'piv', 'generate-certificate', slot, '-P', DEFAULT_PIN,
                '/tmp/test-pub-key.pem', '-s', 'subject-' + algo)
            output = ykman_cli('piv', 'export-certificate', slot, '-')
            cert = x509.load_pem_x509_certificate(output.encode(),
                                                  default_backend())
            _verify_cert(cert, cert.public_key())
            fingerprint = b2a_hex(cert.fingerprint(hashes.SHA256())).decode(
                'ascii')

            output = ykman_cli('piv', 'info')
            self.assertIn('Fingerprint:\t' + fingerprint, output)

    def test_generate_self_signed_slot_9a(self):
        self._test_generate_self_signed('9a')

    def test_generate_self_signed_slot_9c(self):
        self._test_generate_self_signed('9c')

    def test_generate_self_signed_slot_9d(self):
        self._test_generate_self_signed('9d')

    def test_generate_self_signed_slot_9e(self):
        self._test_generate_self_signed('9e')


class ManagementKey(PivTestCase):

    @classmethod
    def setUp(cls):
        ykman_cli('piv', 'reset', '-f')

    def test_change_management_key_protect_random(self):
        ykman_cli(
            'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
            '-m', DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        self.assertIn(
            'Management key is stored on the YubiKey, protected by PIN',
            output)

        with self.assertRaises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                '-m', DEFAULT_MANAGEMENT_KEY)

        # Should succeed - PIN as key
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN)

    def test_change_management_key_protect_prompt(self):
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                  input=DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        self.assertIn(
            'Management key is stored on the YubiKey, protected by PIN',
            output)

        with self.assertRaises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                '-m', DEFAULT_MANAGEMENT_KEY)

        # Should succeed - PIN as key
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN)

    def test_change_management_key_no_protect_random(self):
        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', DEFAULT_MANAGEMENT_KEY)
        self.assertRegex(
            output, re.compile(
                r'^Generated management key: [a-f0-9]{48}$', re.MULTILINE))

        output = ykman_cli('piv', 'info')
        self.assertNotIn('Management key is stored on the YubiKey', output)

    def test_change_management_key_no_protect_arg(self):
        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', DEFAULT_MANAGEMENT_KEY,
            '-n', NON_DEFAULT_MANAGEMENT_KEY)
        self.assertEqual('', output)
        output = ykman_cli('piv', 'info')
        self.assertNotIn('Management key is stored on the YubiKey', output)

        with self.assertRaises(SystemExit):
            ykman_cli(
                'piv', 'change-management-key',
                '-m', DEFAULT_MANAGEMENT_KEY,
                '-n', NON_DEFAULT_MANAGEMENT_KEY)

        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', NON_DEFAULT_MANAGEMENT_KEY,
            '-n', DEFAULT_MANAGEMENT_KEY)
        self.assertEqual('', output)

    def test_change_management_key_no_protect_prompt(self):
        output = ykman_cli('piv', 'change-management-key',
                           input=old_new_new(DEFAULT_MANAGEMENT_KEY,
                                             NON_DEFAULT_MANAGEMENT_KEY))
        self.assertNotIn('Generated', output)
        output = ykman_cli('piv', 'info')
        self.assertNotIn('Management key is stored on the YubiKey', output)

        with self.assertRaises(SystemExit):
            ykman_cli('piv', 'change-management-key',
                      input=old_new_new(DEFAULT_MANAGEMENT_KEY,
                                        NON_DEFAULT_MANAGEMENT_KEY))

        ykman_cli('piv', 'change-management-key',
                  input=old_new_new(NON_DEFAULT_MANAGEMENT_KEY,
                                    DEFAULT_MANAGEMENT_KEY))
        self.assertNotIn('Generated', output)


class Pin(PivTestCase):

    def test_change_pin(self):
        ykman_cli('piv', 'change-pin', '-P', DEFAULT_PIN, '-n', NON_DEFAULT_PIN)
        ykman_cli('piv', 'change-pin', '-P', NON_DEFAULT_PIN, '-n', DEFAULT_PIN)

    def test_change_pin_prompt(self):
        ykman_cli('piv', 'change-pin',
                  input=old_new_new(DEFAULT_PIN, NON_DEFAULT_PIN))
        ykman_cli('piv', 'change-pin',
                  input=old_new_new(NON_DEFAULT_PIN, DEFAULT_PIN))


class Puk(PivTestCase):

    def test_change_puk(self):
        o1 = ykman_cli('piv', 'change-puk', '-p', DEFAULT_PUK,
                       '-n', NON_DEFAULT_PUK)
        self.assertIn('New PUK set.', o1)

        o2 = ykman_cli('piv', 'change-puk', '-p', NON_DEFAULT_PUK,
                       '-n', DEFAULT_PUK)
        self.assertIn('New PUK set.', o2)

        with self.assertRaises(SystemExit):
            ykman_cli('piv', 'change-puk', '-p', NON_DEFAULT_PUK,
                      '-n', DEFAULT_PUK)

    def test_change_puk_prompt(self):
        ykman_cli('piv', 'change-puk',
                  input=old_new_new(DEFAULT_PUK, NON_DEFAULT_PUK))
        ykman_cli('piv', 'change-puk',
                  input=old_new_new(NON_DEFAULT_PUK, DEFAULT_PUK))
