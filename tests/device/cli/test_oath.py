# -*- coding: utf-8 -*-

from base64 import b32encode

import pytest

from ykman.oath import STEAM_CHAR_TABLE
from yubikit.management import CAPABILITY

from .. import condition

URI_HOTP_EXAMPLE = (
    "otpauth://hotp/Example:demo@example.com?"
    "secret=JBSWY3DPK5XXE3DEJ5TE6QKUJA======&issuer=Example&counter=1"
)

URI_TOTP_EXAMPLE = (
    "otpauth://totp/ACME%20Co:john.doe@email.com?"
    "secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"
    "&algorithm=SHA1&digits=6&period=30"
)

URI_TOTP_EXAMPLE_B = (
    "otpauth://totp/ACME%20Co:john.doe.b@email.com?"
    "secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"
    "&algorithm=SHA1&digits=6&period=30"
)

URI_TOTP_EXAMPLE_EXTRA_PARAMETER = (
    "otpauth://totp/ACME%20Co:john.doe.extra@email.com?"
    "secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"
    "&algorithm=SHA1&digits=6&period=30&skid=JKS3424d"
)

PASSWORD = "aaaa"


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.OATH)
def preconditions(ykman_cli):
    ykman_cli("oath", "reset", "-f")


@pytest.fixture()
def password(info):
    if CAPABILITY.OATH in info.fips_capable:
        yield PASSWORD
    else:
        yield None


@pytest.fixture()
def accounts_cli(ykman_cli, password):
    if password:
        ykman_cli("oath", "access", "change", "-n", password)

    def fn(*args, **kwargs):
        argv = ["oath", "accounts", *args]
        if password:
            argv += ["-p", password]
        return ykman_cli(*argv, **kwargs)

    yield fn


class TestOATH:
    def test_oath_info(self, ykman_cli):
        output = ykman_cli("oath", "info").output
        assert "version:" in output

    @condition.yk4_fips(False)
    def test_info_does_not_indicate_fips_mode_for_non_fips_key(self, ykman_cli):
        info = ykman_cli("oath", "info").output
        assert "FIPS:" not in info

    def test_oath_add_credential(self, accounts_cli, password):
        accounts_cli("add", "test-name", "abba")
        creds = accounts_cli("list").output
        assert "test-name" in creds

    def test_oath_add_credential_prompt(self, accounts_cli):
        accounts_cli("add", "test-name-2", input="abba")
        creds = accounts_cli("list").output
        assert "test-name-2" in creds

    def test_oath_add_credential_with_space(self, accounts_cli):
        accounts_cli("add", "test-name-space", "ab ba")
        creds = accounts_cli("list").output
        assert "test-name-space" in creds

    def test_oath_hidden_cred(self, accounts_cli):
        accounts_cli("add", "_hidden:name", "abba")
        creds = accounts_cli("code").output
        assert "_hidden:name" not in creds
        creds = accounts_cli("code", "-H").output
        assert "_hidden:name" in creds

    def test_oath_add_uri_hotp(self, accounts_cli):
        accounts_cli("uri", URI_HOTP_EXAMPLE)
        creds = accounts_cli("list").output
        assert "Example:demo" in creds

    def test_oath_add_uri_totp(self, accounts_cli):
        accounts_cli("uri", URI_TOTP_EXAMPLE)
        creds = accounts_cli("list").output
        assert "john.doe" in creds

    def test_oath_add_uri_totp_extra_parameter(self, accounts_cli):
        accounts_cli("uri", URI_TOTP_EXAMPLE_EXTRA_PARAMETER)
        creds = accounts_cli("list").output
        assert "john.doe.extra" in creds

    def test_oath_add_uri_totp_prompt(self, accounts_cli):
        accounts_cli("uri", input=URI_TOTP_EXAMPLE_B)
        creds = accounts_cli("list").output
        assert "john.doe" in creds

    def test_oath_code(self, accounts_cli):
        accounts_cli("add", "test-name2", "abba")
        creds = accounts_cli("code").output
        assert "test-name2" in creds

    def test_oath_code_query_single(self, accounts_cli):
        accounts_cli("add", "query-me", "abba")
        creds = accounts_cli("code", "query-me").output
        assert "query-me" in creds

    def test_oath_code_query_multiple(self, accounts_cli):
        accounts_cli("add", "foo", "abba")
        accounts_cli("add", "query-me", "abba")
        accounts_cli("add", "bar", "abba")
        lines = accounts_cli("code", "query").output.strip().splitlines()
        assert len(lines) == 1
        assert "query-me" in lines[0]

    def test_oath_reset(self, ykman_cli):
        output = ykman_cli("oath", "reset", "-f").output
        assert "Reset complete" in output

    def test_oath_hotp_vectors_6(self, accounts_cli):
        accounts_cli(
            "add",
            "-o",
            "HOTP",
            "testvector",
            b32encode(b"12345678901234567890").decode(),
        )
        for code in ["755224", "287082", "359152", "969429", "338314"]:
            words = accounts_cli("code", "testvector").output.split()
            assert code in words

    def test_oath_hotp_vectors_8(self, accounts_cli):
        accounts_cli(
            "add",
            "-o",
            "HOTP",
            "-d",
            "8",
            "testvector8",
            b32encode(b"12345678901234567890").decode(),
        )
        for code in ["84755224", "94287082", "37359152", "26969429", "40338314"]:
            words = accounts_cli("code", "testvector8").output.split()
            assert code in words

    def test_oath_hotp_code(self, accounts_cli):
        accounts_cli("add", "-o", "HOTP", "hotp-cred", "abba")
        words = accounts_cli("code", "hotp-cred").output.split()
        assert "659165" in words

    def test_oath_hotp_code_single(self, accounts_cli):
        accounts_cli("add", "-o", "HOTP", "hotp-cred", "abba")
        words = accounts_cli("code", "hotp-cred", "--single").output.split()
        assert "659165" in words

    def test_oath_totp_steam_code(self, accounts_cli):
        accounts_cli("add", "Steam:steam-cred", "abba")
        cred = accounts_cli("code", "steam-cred").output.strip()
        code = cred.split()[-1]
        assert 5 == len(code), f"cred wrong length: {code!r}"
        assert all(c in STEAM_CHAR_TABLE for c in code), (
            f"{code!r} contains non-steam characters"
        )

    def test_oath_totp_steam_code_single(self, accounts_cli):
        accounts_cli("add", "Steam:steam-cred", "abba")
        code = accounts_cli("code", "-s", "steam-cred").output.strip()
        assert 5 == len(code), f"cred wrong length: {code!r}"
        assert all(c in STEAM_CHAR_TABLE for c in code), (
            f"{code!r} contains non-steam characters"
        )

    def test_oath_code_output_no_touch(self, accounts_cli):
        accounts_cli("add", "TOTP:normal", "aaaa")
        accounts_cli("add", "Steam:normal", "aaba")
        accounts_cli("add", "-o", "HOTP", "HOTP:normal", "abaa")

        lines = accounts_cli("code").output.strip().splitlines()
        entries = {line.split()[0]: line for line in lines}
        assert "HOTP Account" in entries["HOTP:normal"]

        code = entries["Steam:normal"].split()[-1]
        assert 5 == len(code), f"cred wrong length: {code!r}"
        assert all(c in STEAM_CHAR_TABLE for c in code), (
            f"{code!r} contains non-steam characters"
        )

        code = entries["TOTP:normal"].split()[-1]
        assert 6 == len(code)
        int(code)

    @condition.min_version(4)
    def test_oath_code_output(self, accounts_cli):
        accounts_cli("add", "TOTP:normal", "aaaa")
        accounts_cli("add", "--touch", "TOTP:touch", "aaab")
        accounts_cli("add", "Steam:normal", "aaba")
        accounts_cli("add", "--touch", "Steam:touch", "aabb")
        accounts_cli("add", "-o", "HOTP", "HOTP:normal", "abaa")

        lines = accounts_cli("code").output.strip().splitlines()
        entries = {line.split()[0]: line for line in lines}
        assert "Requires Touch" in entries["TOTP:touch"]
        assert "Requires Touch" in entries["Steam:touch"]
        assert "HOTP Account" in entries["HOTP:normal"]

        code = entries["Steam:normal"].split()[-1]
        assert 5 == len(code), f"cred wrong length: {code!r}"
        assert all(c in STEAM_CHAR_TABLE for c in code), (
            f"{code!r} contains non-steam characters"
        )

        code = entries["TOTP:normal"].split()[-1]
        assert 6 == len(code)
        int(code)

    @condition.min_version(4)
    def test_oath_totp_steam_touch_not_in_code_output(self, accounts_cli):
        accounts_cli("add", "--touch", "Steam:steam-cred", "abba")
        accounts_cli("add", "TOTP:totp-cred", "abba")
        lines = accounts_cli("code").output.strip().splitlines()
        assert "Requires Touch" in lines[0]

    def test_oath_delete(self, accounts_cli):
        accounts_cli("add", "delete-me", "abba")
        accounts_cli("delete", "delete-me", "-f")
        assert "delete-me" not in accounts_cli("list").output

    def test_oath_unicode(self, accounts_cli):
        accounts_cli("add", "😃", "abba")
        accounts_cli("code")
        accounts_cli("list")
        accounts_cli("delete", "😃", "-f")

    @condition.yk4_fips(False)
    @condition.min_version(4, 3, 1)
    def test_oath_sha512(self, accounts_cli):
        accounts_cli("add", "abba", "abba", "--algorithm", "SHA512")
        accounts_cli("delete", "abba", "-f")

    # NEO credential capacity may vary based on configuration
    @condition.min_version(4)
    def test_add_max_creds(self, accounts_cli, version):
        n_creds = 32 if version < (5, 7, 0) else 64
        for i in range(n_creds):
            accounts_cli("add", "test" + str(i), "abba")
            output = accounts_cli("list").output
            lines = output.strip().split("\n")
            assert len(lines) == i + 1

        with pytest.raises(SystemExit):
            accounts_cli("add", "testx", "abba")

    @condition.min_version(5, 3, 1)
    def test_rename(self, accounts_cli):
        accounts_cli("uri", URI_TOTP_EXAMPLE)
        accounts_cli("rename", "john.doe", "Example:user@example.com", "-f")

        creds = accounts_cli("list").output
        assert "john.doe" not in creds
        assert "Example:user@example.com" in creds


class TestOathFips:
    @pytest.fixture(autouse=True)
    @condition.yk4_fips(True)
    def check_fips(self):
        pass

    def test_no_fips_mode_without_password(self, ykman_cli):
        output = ykman_cli("oath", "info").output
        assert "FIPS Approved Mode: No" in output

    def test_fips_mode_with_password(self, ykman_cli):
        ykman_cli("oath", "access", "change", "-n", PASSWORD)
        output = ykman_cli("oath", "info").output
        assert "FIPS Approved Mode: Yes" in output

    def test_sha512_not_supported(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli(
                "oath", "accounts", "add", "abba", "abba", "--algorithm", "SHA512"
            )


class TestPskc:
    def test_add_with_generate(self, accounts_cli):
        """Test adding a credential with --generate flag."""
        result = accounts_cli("add", "generated-cred", "--generate", "-f")
        assert "Generated credential secret (base32):" in result.output

        creds = accounts_cli("list").output
        assert "generated-cred" in creds

    def test_add_with_generate_and_secret_fails(self, accounts_cli):
        """Test that --generate cannot be used with a provided secret."""
        with pytest.raises(SystemExit):
            accounts_cli("add", "fail-cred", "abba", "--generate", "-f")

    def test_export_to_pskc_file(self, accounts_cli, tmp_path):
        """Test exporting a credential to a PSKC file."""
        pskc_file = tmp_path / "export.pskc"
        accounts_cli(
            "add", "export-test", "GEZDGNBVGY3TQOJQ", "-O", str(pskc_file), "-f"
        )
        assert pskc_file.exists()

        # Verify the file contains expected data
        content = pskc_file.read_text()
        assert "pskc" in content.lower()
        assert "export-test" in content

    def test_export_with_issuer(self, accounts_cli, tmp_path):
        """Test exporting a credential with issuer to a PSKC file."""
        pskc_file = tmp_path / "export_issuer.pskc"
        accounts_cli(
            "add",
            "user@example.com",
            "GEZDGNBVGY3TQOJQ",
            "-i",
            "ExampleIssuer",
            "-O",
            str(pskc_file),
            "-f",
        )
        assert pskc_file.exists()

        content = pskc_file.read_text()
        assert "ExampleIssuer" in content

    def test_export_with_passphrase(self, accounts_cli, tmp_path):
        """Test exporting a credential encrypted with a passphrase."""
        pskc_file = tmp_path / "encrypted_pass.pskc"
        accounts_cli(
            "add",
            "passphrase-test",
            "GEZDGNBVGY3TQOJQ",
            "-O",
            str(pskc_file),
            "--pskc-passphrase",
            "testpassword123",
            "-f",
        )
        assert pskc_file.exists()

        # Verify the file is encrypted (contains encryption info)
        content = pskc_file.read_text()
        assert "EncryptedValue" in content or "CipherData" in content

    def test_export_with_preshared_key(self, accounts_cli, tmp_path):
        """Test exporting a credential encrypted with a pre-shared key."""
        pskc_file = tmp_path / "encrypted_key.pskc"
        # 16 bytes = 32 hex characters
        psk = "0123456789abcdef0123456789abcdef"
        accounts_cli(
            "add",
            "psk-test",
            "GEZDGNBVGY3TQOJQ",
            "-O",
            str(pskc_file),
            "--pskc-key",
            psk,
            "-f",
        )
        assert pskc_file.exists()

        content = pskc_file.read_text()
        assert "EncryptedValue" in content or "CipherData" in content

    def test_export_pskc_passphrase_too_short(self, accounts_cli, tmp_path):
        """Test that passphrase must be at least 8 characters."""
        pskc_file = tmp_path / "fail.pskc"
        with pytest.raises(SystemExit):
            accounts_cli(
                "add",
                "fail-test",
                "GEZDGNBVGY3TQOJQ",
                "-O",
                str(pskc_file),
                "--pskc-passphrase",
                "short",
                "-f",
            )

    def test_export_pskc_key_wrong_length(self, accounts_cli, tmp_path):
        """Test that pre-shared key must be 16 bytes."""
        pskc_file = tmp_path / "fail.pskc"
        with pytest.raises(SystemExit):
            accounts_cli(
                "add",
                "fail-test",
                "GEZDGNBVGY3TQOJQ",
                "-O",
                str(pskc_file),
                "--pskc-key",
                "0123456789abcdef",  # Only 8 bytes
                "-f",
            )

    def test_export_pskc_key_and_passphrase_fails(self, accounts_cli, tmp_path):
        """Test that --pskc-key and --pskc-passphrase cannot be used together."""
        pskc_file = tmp_path / "fail.pskc"
        with pytest.raises(SystemExit):
            accounts_cli(
                "add",
                "fail-test",
                "GEZDGNBVGY3TQOJQ",
                "-O",
                str(pskc_file),
                "--pskc-key",
                "0123456789abcdef0123456789abcdef",
                "--pskc-passphrase",
                "testpassword",
                "-f",
            )

    def test_pskc_encryption_without_output_fails(self, accounts_cli):
        """Test that encryption options require --output."""
        with pytest.raises(SystemExit):
            accounts_cli(
                "add",
                "fail-test",
                "GEZDGNBVGY3TQOJQ",
                "--pskc-passphrase",
                "testpassword123",
                "-f",
            )

    def test_generate_and_export(self, accounts_cli, tmp_path):
        """Test generating a secret and exporting to PSKC."""
        pskc_file = tmp_path / "generated_export.pskc"
        accounts_cli("add", "gen-export-test", "--generate", "-O", str(pskc_file), "-f")
        assert pskc_file.exists()

        creds = accounts_cli("list").output
        assert "gen-export-test" in creds

    def test_import_pskc_file(self, accounts_cli, tmp_path):
        """Test importing credentials from a PSKC file."""
        # First export a credential
        pskc_file = tmp_path / "import_test.pskc"
        accounts_cli(
            "add",
            "to-import",
            "GEZDGNBVGY3TQOJQ",
            "-i",
            "TestIssuer",
            "-O",
            str(pskc_file),
            "-f",
        )

        # Delete the credential
        accounts_cli("delete", "to-import", "-f")
        creds = accounts_cli("list").output
        assert "to-import" not in creds

        # Re-import from PSKC
        accounts_cli("import", str(pskc_file), "-f")
        creds = accounts_cli("list").output
        assert "to-import" in creds

    def test_import_pskc_encrypted_with_passphrase(self, accounts_cli, tmp_path):
        """Test importing credentials from a passphrase-encrypted PSKC file."""
        passphrase = "testpassword123"
        pskc_file = tmp_path / "encrypted_import.pskc"

        # Export with encryption
        accounts_cli(
            "add",
            "encrypted-import",
            "GEZDGNBVGY3TQOJQ",
            "-O",
            str(pskc_file),
            "--pskc-passphrase",
            passphrase,
            "-f",
        )

        # Delete the credential
        accounts_cli("delete", "encrypted-import", "-f")

        # Re-import with passphrase
        accounts_cli("import", str(pskc_file), "-f", input=passphrase)
        creds = accounts_cli("list").output
        assert "encrypted-import" in creds

    def test_import_pskc_encrypted_with_key(self, accounts_cli, tmp_path):
        """Test importing credentials from a key-encrypted PSKC file."""
        psk = "0123456789abcdef0123456789abcdef"
        pskc_file = tmp_path / "key_encrypted_import.pskc"

        # Export with encryption
        accounts_cli(
            "add",
            "key-import",
            "GEZDGNBVGY3TQOJQ",
            "-O",
            str(pskc_file),
            "--pskc-key",
            psk,
            "-f",
        )

        # Delete the credential
        accounts_cli("delete", "key-import", "-f")

        # Re-import with key
        accounts_cli("import", str(pskc_file), "-f", input=psk)
        creds = accounts_cli("list").output
        assert "key-import" in creds

    def test_export_hotp_credential(self, accounts_cli, tmp_path):
        """Test exporting an HOTP credential to PSKC."""
        pskc_file = tmp_path / "hotp_export.pskc"
        accounts_cli(
            "add",
            "hotp-export",
            "GEZDGNBVGY3TQOJQ",
            "-o",
            "HOTP",
            "-c",
            "10",
            "-O",
            str(pskc_file),
            "-f",
        )
        assert pskc_file.exists()

        content = pskc_file.read_text()
        assert "hotp" in content.lower()

    def test_export_totp_with_period(self, accounts_cli, tmp_path):
        """Test exporting a TOTP credential with custom period."""
        pskc_file = tmp_path / "totp_period.pskc"
        accounts_cli(
            "add",
            "totp-period",
            "GEZDGNBVGY3TQOJQ",
            "-P",
            "60",
            "-O",
            str(pskc_file),
            "-f",
        )
        assert pskc_file.exists()

        content = pskc_file.read_text()
        assert "60" in content

    def test_export_with_algorithm(self, accounts_cli, tmp_path):
        """Test exporting a credential with SHA256 algorithm."""
        pskc_file = tmp_path / "sha256_export.pskc"
        accounts_cli(
            "add",
            "sha256-test",
            "GEZDGNBVGY3TQOJQ",
            "-a",
            "SHA256",
            "-O",
            str(pskc_file),
            "-f",
        )
        assert pskc_file.exists()

        content = pskc_file.read_text()
        assert "SHA256" in content

    def test_export_with_digits(self, accounts_cli, tmp_path):
        """Test exporting a credential with 8 digits."""
        pskc_file = tmp_path / "8digits_export.pskc"
        accounts_cli(
            "add",
            "8digits-test",
            "GEZDGNBVGY3TQOJQ",
            "-d",
            "8",
            "-O",
            str(pskc_file),
            "-f",
        )
        assert pskc_file.exists()

        content = pskc_file.read_text()
        assert "8" in content
