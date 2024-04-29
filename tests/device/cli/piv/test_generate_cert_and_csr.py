from binascii import b2a_hex
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from .util import NON_DEFAULT_MANAGEMENT_KEY
from ... import condition
import pytest


def _verify_cert(cert, pubkey):
    cert_signature = cert.signature
    cert_bytes = cert.tbs_certificate_bytes

    if isinstance(pubkey, rsa.RSAPublicKey):
        pubkey.verify(
            cert_signature,
            cert_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        pubkey.verify(
            cert_signature, cert_bytes, ec.ECDSA(cert.signature_hash_algorithm)
        )
    else:
        raise ValueError("Unsupported public key value")


def not_roca(version):
    return not ((4, 2, 0) <= version < (4, 3, 5))


class TestNonDefaultMgmKey:
    @pytest.fixture(autouse=True)
    def set_mgmt_key(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "access",
            "change-management-key",
            "-P",
            keys.pin,
            "-m",
            keys.mgmt,
            "-n",
            NON_DEFAULT_MANAGEMENT_KEY,
        )

    def _test_generate_self_signed(self, ykman_cli, keys, slot, algo):
        pubkey_output = ykman_cli(
            "piv",
            "keys",
            "generate",
            slot,
            "-a",
            algo,
            "-m",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output
        ykman_cli(
            "piv",
            "certificates",
            "generate",
            slot,
            "-m",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-s",
            "subject-" + algo,
            "-P",
            keys.pin,
            "-",
            input=pubkey_output,
        )
        output = ykman_cli("piv", "certificates", "export", slot, "-").output
        cert = x509.load_pem_x509_certificate(output.encode(), default_backend())
        _verify_cert(cert, cert.public_key())
        fingerprint = b2a_hex(cert.fingerprint(hashes.SHA256())).decode("ascii")

        output = ykman_cli("piv", "info").output
        assert fingerprint in output

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9a_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9a", "RSA2048")

    def test_generate_self_signed_slot_9a_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9a", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9c_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9c", "RSA2048")

    def test_generate_self_signed_slot_9c_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9c", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9d_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9d", "RSA2048")

    def test_generate_self_signed_slot_9d_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9d", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9e_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9e", "RSA2048")

    def test_generate_self_signed_slot_9e_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9e", "ECCP256")

    def _test_generate_csr(self, ykman_cli, keys, slot, algo):
        subject_input = "subject-" + algo
        pubkey_output = ykman_cli(
            "piv",
            "keys",
            "generate",
            slot,
            "-a",
            algo,
            "-m",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output
        csr_output = ykman_cli(
            "piv",
            "certificates",
            "request",
            slot,
            "-P",
            keys.pin,
            "-",
            "-",
            "-s",
            subject_input,
            input=pubkey_output,
        ).output
        csr = x509.load_pem_x509_csr(csr_output.encode("utf-8"), default_backend())
        subject_output = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
            0
        ].value

        assert subject_input == subject_output

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9a_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9a", "RSA2048")

    def test_generate_csr_slot_9a_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9a", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9c_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9c", "RSA2048")

    def test_generate_csr_slot_9c_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9c", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9d_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9d", "RSA2048")

    def test_generate_csr_slot_9d_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9d", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9e_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9e", "RSA2048")

    def test_generate_csr_slot_9e_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9e", "ECCP256")


class TestProtectedMgmKey:
    @pytest.fixture(autouse=True)
    def protect_mgmt_key(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "access",
            "change-management-key",
            "-p",
            "-P",
            keys.pin,
            "-m",
            keys.mgmt,
        )

    def _test_generate_self_signed(self, ykman_cli, keys, slot, algo):
        pubkey_output = ykman_cli(
            "piv", "keys", "generate", slot, "-a", algo, "-P", keys.pin, "-"
        ).output
        ykman_cli(
            "piv",
            "certificates",
            "generate",
            slot,
            "-P",
            keys.pin,
            "-s",
            "subject-" + algo,
            "-",
            input=pubkey_output,
        )
        output = ykman_cli("piv", "certificates", "export", slot, "-").output
        cert = x509.load_pem_x509_certificate(output.encode(), default_backend())
        _verify_cert(cert, cert.public_key())
        fingerprint = b2a_hex(cert.fingerprint(hashes.SHA256())).decode("ascii")

        output = ykman_cli("piv", "info").output
        assert fingerprint in output

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9a_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9a", "RSA2048")

    def test_generate_self_signed_slot_9a_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9a", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9c_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9c", "RSA2048")

    def test_generate_self_signed_slot_9c_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9c", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9d_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9d", "RSA2048")

    def test_generate_self_signed_slot_9d_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9d", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_self_signed_slot_9e_rsa2048(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9e", "RSA2048")

    def test_generate_self_signed_slot_9e_eccp256(self, ykman_cli, keys):
        self._test_generate_self_signed(ykman_cli, keys, "9e", "ECCP256")

    def _test_generate_csr(self, ykman_cli, keys, slot, algo):
        subject_input = "subject-" + algo
        pubkey_output = ykman_cli(
            "piv", "keys", "generate", slot, "-a", algo, "-P", keys.pin, "-"
        ).output
        csr_output = ykman_cli(
            "piv",
            "certificates",
            "request",
            slot,
            "-P",
            keys.pin,
            "-",
            "-",
            "-s",
            subject_input,
            input=pubkey_output,
        ).output
        csr = x509.load_pem_x509_csr(csr_output.encode("utf-8"), default_backend())
        subject_output = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
            0
        ].value

        assert subject_input == subject_output

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9a_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9a", "RSA2048")

    def test_generate_csr_slot_9a_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9a", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9c_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9c", "RSA2048")

    def test_generate_csr_slot_9c_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9c", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9d_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9d", "RSA2048")

    def test_generate_csr_slot_9d_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9d", "ECCP256")

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_slot_9e_rsa2048(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9e", "RSA2048")

    def test_generate_csr_slot_9e_eccp256(self, ykman_cli, keys):
        self._test_generate_csr(ykman_cli, keys, "9e", "ECCP256")
