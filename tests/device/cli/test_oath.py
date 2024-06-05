# -*- coding: utf-8 -*-

from ykman.oath import STEAM_CHAR_TABLE
from yubikit.management import CAPABILITY
from .. import condition
from base64 import b32encode
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
        assert all(
            c in STEAM_CHAR_TABLE for c in code
        ), f"{code!r} contains non-steam characters"

    def test_oath_totp_steam_code_single(self, accounts_cli):
        accounts_cli("add", "Steam:steam-cred", "abba")
        code = accounts_cli("code", "-s", "steam-cred").output.strip()
        assert 5 == len(code), f"cred wrong length: {code!r}"
        assert all(
            c in STEAM_CHAR_TABLE for c in code
        ), f"{code!r} contains non-steam characters"

    def test_oath_code_output_no_touch(self, accounts_cli):
        accounts_cli("add", "TOTP:normal", "aaaa")
        accounts_cli("add", "Steam:normal", "aaba")
        accounts_cli("add", "-o", "HOTP", "HOTP:normal", "abaa")

        lines = accounts_cli("code").output.strip().splitlines()
        entries = {line.split()[0]: line for line in lines}
        assert "HOTP Account" in entries["HOTP:normal"]

        code = entries["Steam:normal"].split()[-1]
        assert 5 == len(code), f"cred wrong length: {code!r}"
        assert all(
            c in STEAM_CHAR_TABLE for c in code
        ), f"{code!r} contains non-steam characters"

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
        assert all(
            c in STEAM_CHAR_TABLE for c in code
        ), f"{code!r} contains non-steam characters"

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
