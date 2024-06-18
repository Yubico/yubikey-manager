from yubikit.core import TRANSPORT
from yubikit.core.smartcard import ApduError
from ykman.util import parse_certificates
from .. import condition
from ...util import open_file
from cryptography import x509

import pytest


@pytest.fixture(autouse=True)
@condition.min_version(5, 7, 2)
def preconditions(info, transport, ykman_cli):
    if info.is_fips and transport != TRANSPORT.USB:
        pytest.skip("SCP management on YK FIPS over NFC")
    ykman_cli("sd", "reset", "-f")


class TestKeyManagement:
    def test_replace_kvn(self, ykman_cli):
        key = "01" * 16
        keys = f"{key}:{key}:{key}"

        # Replace default SCP03 keyset
        ykman_cli("--scp-sd", "1", "0", "sd", "keys", "import", "scp03", "2", keys)

        # Generate new SCP11a key
        ykman_cli("--scp", keys, "sd", "keys", "generate", "scp11a", "3", "-")

        for i in range(3, 8):
            ykman_cli(
                "--scp",
                keys,
                "sd",
                "keys",
                "generate",
                "scp11a",
                str(i + 1),
                "-r",
                str(i),
                "-",
            )

    def test_scp11a(self, ykman_cli):
        with pytest.raises(ValueError):
            with open_file("scp/oce.pfx") as f:
                ykman_cli("--scp", f.name, "--scp-password", "password", "sd", "info")

        key = "01" * 16
        keys = f"{key}:{key}:{key}"

        # Replace default SCP03 keyset
        ykman_cli("--scp-sd", "1", "0", "sd", "keys", "import", "scp03", "2", keys)

        # Delete SCP11b key, generate SCP11a key
        ykman_cli("--scp", keys, "sd", "keys", "delete", "--force", "scp11b", "0")
        ykman_cli("--scp", keys, "sd", "keys", "generate", "scp11a", "3", "-")

        # Import OCE CA
        with open_file("scp/cert.ca-kloc.ecdsa.pem") as f:
            ykman_cli("--scp", keys, "sd", "keys", "import", "0x10", "3", f.name)

        # Authenticate
        with open_file("scp/oce.pfx") as f:
            certificates = parse_certificates(f.read(), b"password")
            serials = [c.serial_number for c in certificates]

            # Set to ok allowlist
            ykman_cli(
                "--scp",
                f.name,
                "--scp-password",
                "password",
                "sd",
                "keys",
                "set-allowlist",
                "0x10",
                "3",
                *(str(s) for s in serials),
            )

            # Set bad allowlist
            ykman_cli(
                "--scp",
                f.name,
                "--scp-password",
                "password",
                "sd",
                "keys",
                "set-allowlist",
                "0x10",
                "3",
                "123456789",
            )

            with pytest.raises(ApduError):
                ykman_cli("--scp", f.name, "--scp-password", "password", "sd", "info")

            # Remove allowlist
            ykman_cli(
                "--scp",
                keys,
                "sd",
                "keys",
                "set-allowlist",
                "0x10",
                "3",
            )

            ykman_cli(
                "--scp",
                f.name,
                "--scp-password",
                "password",
                "--scp-oce",
                "0x10",
                "3",
                "sd",
                "keys",
                "delete",
                "--force",
                "0x10",
                "3",
            )

    def test_scp11b_specify_kvn(self, ykman_cli):
        ykman_cli("--scp-sd", "1", "0", "sd", "keys", "generate", "scp11b", "2", "-")
        ykman_cli("--scp-sd", "0x13", "1", "sd", "info")
        ykman_cli("--scp-sd", "0x13", "2", "sd", "info")

    def test_scp11b_export(self, ykman_cli):
        ykman_cli("--scp-sd", "1", "0", "sd", "keys", "generate", "scp11b", "2", "-")
        pem = ykman_cli("sd", "keys", "export", "scp11b", "2", "-").output.encode()

        x509.load_pem_x509_certificate(pem)
