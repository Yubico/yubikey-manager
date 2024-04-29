from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from yubikit.core import NotSupportedError
from yubikit.management import CAPABILITY
from ... import condition
import tempfile
import os
import pytest


def generate_pem_eccp256_keypair():
    pk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return (
        pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def roca(version):
    """Not ROCA affected"""
    return (4, 2, 0) <= version < (4, 3, 5)


def not_roca(version):
    """ROCA affected"""
    return not roca(version)


@pytest.fixture()
def tmp_file():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    yield tmp.name
    os.remove(tmp.name)


class TestKeyExport:
    @condition.min_version(5, 3)
    def test_from_metadata(self, ykman_cli, keys):
        pair = generate_pem_eccp256_keypair()

        ykman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            keys.mgmt,
            "-",
            input=pair[0],
        )
        exported = ykman_cli("piv", "keys", "export", "9a", "-").stdout_bytes
        assert exported == pair[1]

    @condition.min_version(4, 3)
    def test_from_metadata_or_attestation(self, ykman_cli, keys):
        der = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-F",
            "der",
            "-m",
            keys.mgmt,
            "-",
        ).stdout_bytes
        exported = ykman_cli(
            "piv", "keys", "export", "9a", "-F", "der", "-"
        ).stdout_bytes
        assert der == exported

    def test_from_metadata_or_cert(self, ykman_cli, keys):
        private_key_pem, public_key_pem = generate_pem_eccp256_keypair()
        ykman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            keys.mgmt,
            "-",
            input=private_key_pem,
        )
        ykman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
            "-s",
            "test",
            input=public_key_pem,
        )

        exported = ykman_cli("piv", "keys", "export", "9a", "-").stdout_bytes

        assert public_key_pem == exported

    @condition.max_version(5, 2, 9)
    def test_from_cert_verify(self, ykman_cli, keys):
        private_key_pem, public_key_pem = generate_pem_eccp256_keypair()
        ykman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            keys.mgmt,
            "-",
            input=private_key_pem,
        )
        ykman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
            "-s",
            "test",
            input=public_key_pem,
        )
        ykman_cli("piv", "keys", "export", "9a", "--verify", "-P", keys.pin, "-")

    @condition.max_version(5, 2, 9)
    def test_from_cert_verify_fails(self, ykman_cli, keys):
        private_key_pem = generate_pem_eccp256_keypair()[0]
        public_key_pem = generate_pem_eccp256_keypair()[1]
        ykman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            keys.mgmt,
            "-",
            input=private_key_pem,
        )
        ykman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
            "-s",
            "test",
            input=public_key_pem,
        )
        with pytest.raises(SystemExit):
            ykman_cli("piv", "keys", "export", "9a", "--verify", "-P", keys.pin, "-")


class TestKeyManagement:
    @condition.check(not_roca)
    def test_generate_key_default(self, ykman_cli, keys):
        output = ykman_cli("piv", "keys", "generate", "9a", "-m", keys.mgmt, "-").output
        assert "BEGIN PUBLIC KEY" in output

    @condition.check(roca)
    def test_generate_key_default_cve201715361(self, ykman_cli, keys):
        with pytest.raises(NotSupportedError):
            ykman_cli("piv", "keys", "generate", "9a", "-m", keys.mgmt, "-")

    @condition.check(not_roca)
    @condition.yk4_fips(False)
    def test_generate_key_rsa1024(self, ykman_cli, info, keys):
        if CAPABILITY.PIV in info.fips_capable:
            pytest.skip("RSA1024 not available on FIPS")

        output = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "RSA1024",
            "-m",
            keys.mgmt,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.check(not_roca)
    def test_generate_key_rsa2048(self, ykman_cli, keys):
        output = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "RSA2048",
            "-m",
            keys.mgmt,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.yk4_fips(False)
    @condition.check(roca)
    def test_generate_key_rsa1024_cve201715361(self, ykman_cli, keys):
        with pytest.raises(NotSupportedError):
            ykman_cli(
                "piv",
                "keys",
                "generate",
                "9a",
                "-a",
                "RSA1024",
                "-m",
                keys.mgmt,
                "-",
            )

    @condition.check(roca)
    def test_generate_key_rsa2048_cve201715361(self, ykman_cli, keys):
        with pytest.raises(NotSupportedError):
            ykman_cli(
                "piv",
                "keys",
                "generate",
                "9a",
                "-a",
                "RSA2048",
                "-m",
                keys.mgmt,
                "-",
            )

    def test_generate_key_eccp256(self, ykman_cli, keys):
        output = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            keys.mgmt,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    def test_import_key_eccp256(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            keys.mgmt,
            "-",
            input=generate_pem_eccp256_keypair()[0],
        )

    @condition.min_version(4)
    def test_generate_key_eccp384(self, ykman_cli, keys):
        output = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP384",
            "-m",
            keys.mgmt,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.min_version(4)
    def test_generate_key_pin_policy_always(self, ykman_cli, keys):
        output = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "--pin-policy",
            "ALWAYS",
            "-m",
            keys.mgmt,
            "-a",
            "ECCP256",
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.min_version(4)
    def test_import_key_pin_policy_always(self, ykman_cli, keys):
        for pin_policy in ["ALWAYS", "always"]:
            ykman_cli(
                "piv",
                "keys",
                "import",
                "9a",
                "--pin-policy",
                pin_policy,
                "-m",
                keys.mgmt,
                "-",
                input=generate_pem_eccp256_keypair()[0],
            )

    @condition.min_version(4)
    def test_generate_key_touch_policy_always(self, ykman_cli, keys):
        output = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "--touch-policy",
            "ALWAYS",
            "-m",
            keys.mgmt,
            "-a",
            "ECCP256",
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.min_version(4)
    def test_import_key_touch_policy_always(self, ykman_cli, keys):
        for touch_policy in ["ALWAYS", "always"]:
            ykman_cli(
                "piv",
                "keys",
                "import",
                "9a",
                "--touch-policy",
                touch_policy,
                "-m",
                keys.mgmt,
                "-",
                input=generate_pem_eccp256_keypair()[0],
            )

    @condition.min_version(4, 3)
    def test_attest_key(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            keys.mgmt,
            "-",
        )
        output = ykman_cli("piv", "keys", "attest", "9a", "-").output
        assert "BEGIN CERTIFICATE" in output

    def _test_generate_csr(self, ykman_cli, keys, tmp_file, algo):
        ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            algo,
            "-m",
            keys.mgmt,
            tmp_file,
        )
        output = ykman_cli(
            "piv",
            "certificates",
            "request",
            "9a",
            tmp_file,
            "-s",
            "test-subject",
            "-P",
            keys.pin,
            "-",
        ).output
        csr = x509.load_pem_x509_csr(output.encode(), default_backend())
        assert csr.is_signature_valid

    @condition.yk4_fips(False)
    @condition.check(not_roca)
    def test_generate_csr_rsa1024(self, ykman_cli, keys, info, tmp_file):
        if CAPABILITY.PIV in info.fips_capable:
            pytest.skip("RSA1024 not available on FIPS")

        self._test_generate_csr(ykman_cli, keys, tmp_file, "RSA1024")

    def test_generate_csr_eccp256(self, ykman_cli, keys, tmp_file):
        self._test_generate_csr(ykman_cli, keys, tmp_file, "ECCP256")

    def test_import_verify_correct_cert_succeeds_with_pin(
        self, ykman_cli, keys, tmp_file
    ):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            keys.mgmt,
            "-",
        ).output

        ykman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
            "-s",
            "test",
            input=public_key_pem,
        )

        ykman_cli("piv", "certificates", "export", "9a", tmp_file)

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "certificates",
                "import",
                "--verify",
                "9a",
                tmp_file,
                "-m",
                keys.mgmt,
            )

        ykman_cli(
            "piv",
            "certificates",
            "import",
            "--verify",
            "9a",
            tmp_file,
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
        )
        ykman_cli(
            "piv",
            "certificates",
            "import",
            "--verify",
            "9a",
            tmp_file,
            "-m",
            keys.mgmt,
            input=keys.pin,
        )

    def test_import_verify_wrong_cert_fails(self, ykman_cli, keys):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            keys.mgmt,
            "-",
        ).output

        ykman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
            "-s",
            "test",
            input=public_key_pem,
        )

        cert_pem = ykman_cli("piv", "certificates", "export", "9a", "-").output

        # Overwrite the key with a new one
        ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            keys.mgmt,
            "-",
            input=public_key_pem,
        )

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "certificates",
                "import",
                "--verify",
                "9a",
                "-",
                "-m",
                keys.mgmt,
                "-P",
                keys.pin,
                input=cert_pem,
            )

    def test_import_no_verify_wrong_cert_succeeds(self, ykman_cli, keys):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            keys.mgmt,
            "-",
        ).output

        ykman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
            "-s",
            "test",
            input=public_key_pem,
        )

        cert_pem = ykman_cli("piv", "certificates", "export", "9a", "-").output

        # Overwrite the key with a new one
        ykman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            keys.mgmt,
            "-",
            input=public_key_pem,
        )

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "certificates",
                "import",
                "--verify",
                "9a",
                "-",
                "-m",
                keys.mgmt,
                "-P",
                keys.pin,
                input=cert_pem,
            )

        ykman_cli(
            "piv",
            "certificates",
            "import",
            "9a",
            "-",
            "-m",
            keys.mgmt,
            "-P",
            keys.pin,
            input=cert_pem,
        )

    @condition.min_version(4, 3)
    def test_export_attestation_certificate(self, ykman_cli):
        output = ykman_cli("piv", "certificates", "export", "f9", "-").output
        assert "BEGIN CERTIFICATE" in output
