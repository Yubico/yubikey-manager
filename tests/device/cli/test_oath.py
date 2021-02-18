# -*- coding: utf-8 -*-

from ykman.oath import STEAM_CHAR_TABLE
from yubikit.management import CAPABILITY
from .. import condition
from base64 import b32encode
import contextlib
import io
import pytest


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


class TestOATH:
    def test_oath_info(self, ykman_cli):
        output = ykman_cli("oath", "info").output
        assert "version:" in output

    @condition.fips(False)
    def test_info_does_not_indicate_fips_mode_for_non_fips_key(self, ykman_cli):
        info = ykman_cli("oath", "info").output
        assert "FIPS:" not in info

    def test_oath_add_credential(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "test-name", "abba")
        creds = ykman_cli("oath", "accounts", "list").output
        assert "test-name" in creds

    def test_oath_add_credential_prompt(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "test-name-2", input="abba")
        creds = ykman_cli("oath", "accounts", "list").output
        assert "test-name-2" in creds

    def test_oath_add_credential_with_space(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "test-name-space", "ab ba")
        creds = ykman_cli("oath", "accounts", "list").output
        assert "test-name-space" in creds

    def test_oath_add_credential_alias(self, ykman_cli):
        with io.StringIO() as buf:
            with contextlib.redirect_stderr(buf):
                ykman_cli("oath", "add", "test-name", "abba")
                ykman_cli("oath", "code", "test-name")
                creds = ykman_cli("oath", "list").output
                ykman_cli("oath", "delete", "test-name", "-f")
            err = buf.getvalue()
        assert "test-name" in creds
        assert "oath accounts add" in err
        assert "oath accounts code" in err
        assert "oath accounts list" in err
        assert "oath accounts delete" in err

    def test_oath_hidden_cred(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "_hidden:name", "abba")
        creds = ykman_cli("oath", "accounts", "code").output
        assert "_hidden:name" not in creds
        creds = ykman_cli("oath", "accounts", "code", "-H").output
        assert "_hidden:name" in creds

    def test_oath_add_uri_hotp(self, ykman_cli):
        ykman_cli("oath", "accounts", "uri", URI_HOTP_EXAMPLE)
        creds = ykman_cli("oath", "accounts", "list").output
        assert "Example:demo" in creds

    def test_oath_add_uri_totp(self, ykman_cli):
        ykman_cli("oath", "accounts", "uri", URI_TOTP_EXAMPLE)
        creds = ykman_cli("oath", "accounts", "list").output
        assert "john.doe" in creds

    def test_oath_add_uri_totp_extra_parameter(self, ykman_cli):
        ykman_cli("oath", "accounts", "uri", URI_TOTP_EXAMPLE_EXTRA_PARAMETER)
        creds = ykman_cli("oath", "accounts", "list").output
        assert "john.doe.extra" in creds

    def test_oath_add_uri_totp_prompt(self, ykman_cli):
        ykman_cli("oath", "accounts", "uri", input=URI_TOTP_EXAMPLE_B)
        creds = ykman_cli("oath", "accounts", "list").output
        assert "john.doe" in creds

    def test_oath_code(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "test-name2", "abba")
        creds = ykman_cli("oath", "accounts", "code").output
        assert "test-name2" in creds

    def test_oath_code_query(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "query-me", "abba")
        creds = ykman_cli("oath", "accounts", "code", "query-me").output
        assert "query-me" in creds

    def test_oath_reset(self, ykman_cli):
        output = ykman_cli("oath", "reset", "-f").output
        assert "Success! All OATH accounts have been deleted from the YubiKey" in output

    def test_oath_hotp_vectors_6(self, ykman_cli):
        ykman_cli(
            "oath",
            "accounts",
            "add",
            "-o",
            "HOTP",
            "testvector",
            b32encode(b"12345678901234567890").decode(),
        )
        for code in ["755224", "287082", "359152", "969429", "338314"]:
            words = ykman_cli("oath", "accounts", "code", "testvector").output.split()
            assert code in words

    def test_oath_hotp_vectors_8(self, ykman_cli):
        ykman_cli(
            "oath",
            "accounts",
            "add",
            "-o",
            "HOTP",
            "-d",
            "8",
            "testvector8",
            b32encode(b"12345678901234567890").decode(),
        )
        for code in ["84755224", "94287082", "37359152", "26969429", "40338314"]:
            words = ykman_cli("oath", "accounts", "code", "testvector8").output.split()
            assert code in words

    def test_oath_hotp_code(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "-o", "HOTP", "hotp-cred", "abba")
        words = ykman_cli("oath", "accounts", "code", "hotp-cred").output.split()
        assert "659165" in words

    def test_oath_totp_steam_code(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "-o", "TOTP", "Steam:steam-cred", "abba")
        cred = ykman_cli("oath", "accounts", "code", "-s", "steam-cred").output.strip()
        assert 5, len(cred) == f"cred wrong length: {cred!r}"
        assert all(
            c in STEAM_CHAR_TABLE for c in cred
        ), f"{cred!r} contains non-steam characters"

    def test_oath_delete(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "delete-me", "abba")
        ykman_cli("oath", "accounts", "delete", "delete-me", "-f")
        assert "delete-me", ykman_cli("oath", "accounts" not in "list")

    def test_oath_unicode(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "😃", "abba")
        ykman_cli("oath", "accounts", "code")
        ykman_cli("oath", "accounts", "list")
        ykman_cli("oath", "accounts", "delete", "😃", "-f")

    @condition.fips(False)
    @condition.min_version(4, 3, 1)
    def test_oath_sha512(self, ykman_cli):
        ykman_cli("oath", "accounts", "add", "abba", "abba", "--algorithm", "SHA512")
        ykman_cli("oath", "accounts", "delete", "abba", "-f")

    # NEO credential capacity may vary based on configuration
    @condition.min_version(4)
    def test_add_32_creds(self, ykman_cli):
        for i in range(32):
            ykman_cli("oath", "accounts", "add", "test" + str(i), "abba")
            output = ykman_cli("oath", "accounts", "list").output
            lines = output.strip().split("\n")
            assert len(lines) == i + 1

        with pytest.raises(SystemExit):
            ykman_cli("oath", "accounts", "add", "testx", "abba")

    @condition.min_version(5, 3, 1)
    def test_rename(self, ykman_cli):
        ykman_cli("oath", "accounts", "uri", URI_TOTP_EXAMPLE)
        ykman_cli(
            "oath", "accounts", "rename", "john.doe", "Example:user@example.com", "-f"
        )

        creds = ykman_cli("oath", "accounts", "list").output
        assert "john.doe" not in creds
        assert "Example:user@example.com" in creds


class TestOathFips:
    @pytest.fixture(autouse=True)
    @condition.fips(True)
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
