import unittest
from binascii import b2a_hex
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from ..framework import cli_test_suite, yubikey_conditions
from .util import (
    DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY, NON_DEFAULT_MANAGEMENT_KEY)


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


@cli_test_suite
def additional_tests(ykman_cli):
    class NonDefaultMgmKey(unittest.TestCase):

        @classmethod
        def setUpClass(cls):
            ykman_cli('piv', 'reset', '-f')
            ykman_cli('piv', 'change-management-key', '-P', DEFAULT_PIN,
                      '-m', DEFAULT_MANAGEMENT_KEY,
                      '-n', NON_DEFAULT_MANAGEMENT_KEY)

        def _test_generate_self_signed(self, slot, algo):
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

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9a_rsa1024(self):
            self._test_generate_self_signed('9a', 'RSA1024')

        def test_generate_self_signed_slot_9a_eccp256(self):
            self._test_generate_self_signed('9a', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9c_rsa1024(self):
            self._test_generate_self_signed('9c', 'RSA1024')

        def test_generate_self_signed_slot_9c_eccp256(self):
            self._test_generate_self_signed('9c', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9d_rsa1024(self):
            self._test_generate_self_signed('9d', 'RSA1024')

        def test_generate_self_signed_slot_9d_eccp256(self):
            self._test_generate_self_signed('9d', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9e_rsa1024(self):
            self._test_generate_self_signed('9e', 'RSA1024')

        def test_generate_self_signed_slot_9e_eccp256(self):
            self._test_generate_self_signed('9e', 'ECCP256')

        def _test_generate_csr(self, slot, algo):
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

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9a_rsa1024(self):
            self._test_generate_csr('9a', 'RSA1024')

        def test_generate_csr_slot_9a_eccp256(self):
            self._test_generate_csr('9a', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9c_rsa1024(self):
            self._test_generate_csr('9c', 'RSA1024')

        def test_generate_csr_slot_9c_eccp256(self):
            self._test_generate_csr('9c', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9d_rsa1024(self):
            self._test_generate_csr('9d', 'RSA1024')

        def test_generate_csr_slot_9d_eccp256(self):
            self._test_generate_csr('9d', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9e_rsa1024(self):
            self._test_generate_csr('9e', 'RSA1024')

        def test_generate_csr_slot_9e_eccp256(self):
            self._test_generate_csr('9e', 'ECCP256')

    class ProtectedMgmKey(unittest.TestCase):

        @classmethod
        def setUpClass(cls):
            ykman_cli('piv', 'reset', '-f')
            ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                      '-m', DEFAULT_MANAGEMENT_KEY)

        def _test_generate_self_signed(self, slot, algo):
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

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9a_rsa1024(self):
            self._test_generate_self_signed('9a', 'RSA1024')

        def test_generate_self_signed_slot_9a_eccp256(self):
            self._test_generate_self_signed('9a', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9c_rsa1024(self):
            self._test_generate_self_signed('9c', 'RSA1024')

        def test_generate_self_signed_slot_9c_eccp256(self):
            self._test_generate_self_signed('9c', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9d_rsa1024(self):
            self._test_generate_self_signed('9d', 'RSA1024')

        def test_generate_self_signed_slot_9d_eccp256(self):
            self._test_generate_self_signed('9d', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_self_signed_slot_9e_rsa1024(self):
            self._test_generate_self_signed('9e', 'RSA1024')

        def test_generate_self_signed_slot_9e_eccp256(self):
            self._test_generate_self_signed('9e', 'ECCP256')

        def _test_generate_csr(self, slot, algo):
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

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9a_rsa1024(self):
            self._test_generate_csr('9a', 'RSA1024')

        def test_generate_csr_slot_9a_eccp256(self):
            self._test_generate_csr('9a', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9c_rsa1024(self):
            self._test_generate_csr('9c', 'RSA1024')

        def test_generate_csr_slot_9c_eccp256(self):
            self._test_generate_csr('9c', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9d_rsa1024(self):
            self._test_generate_csr('9d', 'RSA1024')

        def test_generate_csr_slot_9d_eccp256(self):
            self._test_generate_csr('9d', 'ECCP256')

        @yubikey_conditions.is_not_fips
        @yubikey_conditions.is_not_roca
        def test_generate_csr_slot_9e_rsa1024(self):
            self._test_generate_csr('9e', 'RSA1024')

        def test_generate_csr_slot_9e_eccp256(self):
            self._test_generate_csr('9e', 'ECCP256')

    return [
        NonDefaultMgmKey,
        ProtectedMgmKey,
    ]
