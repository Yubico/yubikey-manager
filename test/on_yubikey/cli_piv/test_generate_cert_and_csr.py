import unittest
from binascii import b2a_hex
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from ..util import ykman_cli, is_fips
from .util import (
    PivTestCase, DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY,
    NON_DEFAULT_MANAGEMENT_KEY)


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


class NonDefaultMgmKey(PivTestCase):

    @classmethod
    def setUpClass(cls):
        ykman_cli('piv', 'reset', '-f')
        ykman_cli('piv', 'change-management-key', '-P', DEFAULT_PIN,
                  '-m', DEFAULT_MANAGEMENT_KEY,
                  '-n', NON_DEFAULT_MANAGEMENT_KEY)

    def _test_generate_self_signed(self, slot):
        for algo in ('ECCP256', 'RSA1024'):
            pubkey_output = ykman_cli(
                'piv', 'generate-key', slot, '-a', algo, '-m',
                NON_DEFAULT_MANAGEMENT_KEY, '-')
            ykman_cli(
                'piv', 'generate-certificate', slot, '-m',
                NON_DEFAULT_MANAGEMENT_KEY,
                '-s', 'subject-' + algo, '-P', DEFAULT_PIN,
                '-', input=pubkey_output)
            output = ykman_cli('piv', 'export-certificate', slot, '-')
            cert = x509.load_pem_x509_certificate(output.encode(),
                                                  default_backend())
            _verify_cert(cert, cert.public_key())
            fingerprint = b2a_hex(cert.fingerprint(hashes.SHA256())).decode(
                'ascii')

            output = ykman_cli('piv', 'info')
            self.assertIn('Fingerprint:\t' + fingerprint, output)

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9a(self):
        self._test_generate_self_signed('9a')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9c(self):
        self._test_generate_self_signed('9c')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9d(self):
        self._test_generate_self_signed('9d')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9e(self):
        self._test_generate_self_signed('9e')

    def _test_generate_csr(self, slot):
        for algo in ('ECCP256', 'RSA1024'):
            subject_input = 'subject-' + algo
            pubkey_output = ykman_cli(
                'piv', 'generate-key', slot, '-a', algo,
                '-m', NON_DEFAULT_MANAGEMENT_KEY, '-')
            csr_output = ykman_cli(
                'piv', 'generate-csr', slot, '-P', DEFAULT_PIN,
                '-', '-', '-s', subject_input, input=pubkey_output)
            csr = x509.load_pem_x509_csr(csr_output.encode('utf-8'),
                                         default_backend())
            subject_output = csr.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)[0].value

            self.assertEqual(subject_input, subject_output)

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9a(self):
        self._test_generate_csr('9a')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9c(self):
        self._test_generate_csr('9c')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9d(self):
        self._test_generate_csr('9d')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9e(self):
        self._test_generate_csr('9e')


class ProtectedMgmKey(PivTestCase):

    @classmethod
    def setUpClass(cls):
        ykman_cli('piv', 'reset', '-f')
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                  '-m', DEFAULT_MANAGEMENT_KEY)

    def _test_generate_self_signed(self, slot):
        for algo in ('ECCP256', 'RSA1024'):
            pubkey_output = ykman_cli(
                'piv', 'generate-key', slot, '-a', algo, '-P', DEFAULT_PIN,
                '-')
            ykman_cli(
                'piv', 'generate-certificate', slot, '-P', DEFAULT_PIN,
                '-s', 'subject-' + algo,
                '-', input=pubkey_output)
            output = ykman_cli('piv', 'export-certificate', slot, '-')
            cert = x509.load_pem_x509_certificate(output.encode(),
                                                  default_backend())
            _verify_cert(cert, cert.public_key())
            fingerprint = b2a_hex(cert.fingerprint(hashes.SHA256())).decode(
                'ascii')

            output = ykman_cli('piv', 'info')
            self.assertIn('Fingerprint:\t' + fingerprint, output)

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9a(self):
        self._test_generate_self_signed('9a')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9c(self):
        self._test_generate_self_signed('9c')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9d(self):
        self._test_generate_self_signed('9d')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_self_signed_slot_9e(self):
        self._test_generate_self_signed('9e')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def _test_generate_csr(self, slot):
        for algo in ('ECCP256', 'RSA1024'):
            subject_input = 'subject-' + algo
            pubkey_output = ykman_cli(
                'piv', 'generate-key', slot, '-a', algo, '-P', DEFAULT_PIN,
                '-')
            csr_output = ykman_cli(
                'piv', 'generate-csr', slot, '-P', DEFAULT_PIN,
                '-', '-', '-s', subject_input, input=pubkey_output)
            csr = x509.load_pem_x509_csr(csr_output.encode('utf-8'),
                                         default_backend())
            subject_output = csr.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)[0].value

            self.assertEqual(subject_input, subject_output)

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9a(self):
        self._test_generate_csr('9a')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9c(self):
        self._test_generate_csr('9c')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9d(self):
        self._test_generate_csr('9d')

    @unittest.skipIf(is_fips(), 'Not applicable to YubiKey FIPS.')
    def test_generate_csr_slot_9e(self):
        self._test_generate_csr('9e')
