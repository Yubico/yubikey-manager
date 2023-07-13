# -*- coding: utf-8 -*-
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yubikit.management import CAPABILITY
from .. import condition

import pytest
import re
import os
import tempfile

DEFAULT_MANAGEMENT_KEY = "00000000000000000000000000000000"
NON_DEFAULT_MANAGEMENT_KEY = "11111111111111111111111111111111"


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


@pytest.fixture()
def eccp256_keypair():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    private_key, public_key = generate_pem_eccp256_keypair()
    tmp.write(private_key)
    tmp.close()
    yield tmp.name, public_key
    os.remove(tmp.name)


@pytest.fixture
def eccp256_public_key():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    _, public_key = generate_pem_eccp256_keypair()
    tmp.write(public_key)
    tmp.close()
    yield tmp.name
    os.remove(tmp.name)


@pytest.fixture()
def tmp_file():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    yield tmp
    os.remove(tmp.name)


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.OATH)
@condition.min_version(5, 4, 3)
def preconditions(ykman_cli):
    ykman_cli("hsmauth", "reset", "-f")


class TestOATH:
    def test_hsmauth_info(self, ykman_cli):
        output = ykman_cli("hsmauth", "info").output
        assert "version:" in output

    def test_hsmauth_reset(self, ykman_cli):
        output = ykman_cli("hsmauth", "reset", "-f").output
        assert (
            "Success! All YubiHSM Auth data have been cleared from the YubiKey."
            in output
        )


class TestCredentials:
    def test_hsmauth_add_credential_symmetric(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-sym",
            "-c",
            "123456",
            "-d",
            "password",
        )
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name" in creds
        assert "38" in creds

    @condition.min_version(5, 6)
    def test_hsmauth_add_credential_asymmetric(self, ykman_cli, eccp256_keypair):
        private_key_file, public_key = eccp256_keypair
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-asym",
            "-c",
            "123456",
            "-p",
            private_key_file,
        )
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name-asym" in creds
        assert "39" in creds

        public_key_exported = ykman_cli(
            "hsmauth", "credentials", "get-public-key", "test-name-asym"
        ).stdout_bytes
        assert public_key == public_key_exported

    def test_hsmauth_add_credential_prompt(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-2",
            "-d",
            "password",
            input="123456",
        )
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name-2" in creds

    def test_hsmauth_add_credential_touch_required(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-3",
            "-c",
            "123456",
            "-d",
            "password",
            "-t",
        )
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name-3" in creds
        assert "On" in creds

    def test_hsmauth_add_credential_wrong_parameter_combo(self, ykman_cli):
        key_enc = "090b47dbed595654901dee1cc655e420"
        key_mac = "592fd483f759e29909a04c4505d2ce0a"

        # Providing derivation password, key_enc and key_mac together
        # should fail
        with pytest.raises(SystemExit):
            ykman_cli(
                "hsmauth",
                "credentials",
                "add",
                "test-name-4",
                "-c",
                "123456",
                "-d",
                "password",
                "-E",
                key_enc,
                "-M",
                key_mac,
            )

    @condition.min_version(5, 6)
    def test_get_public_key_to_file(self, ykman_cli, eccp256_keypair, tmp_file):
        private_key_file, public_key = eccp256_keypair
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-asym",
            "-c",
            "123456",
            "-p",
            private_key_file,
        )

        ykman_cli(
            "hsmauth",
            "credentials",
            "get-public-key",
            "test-name-asym",
            "-o",
            tmp_file.name,
        )

        public_key_from_file = tmp_file.read()
        assert public_key_from_file == public_key

    @condition.min_version(5, 6)
    def test_get_public_key_symmetric_credential(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-sym",
            "-c",
            "123456",
            "-d",
            "password",
        )

        with pytest.raises(SystemExit):
            ykman_cli("hsmauth", "credentials", "test-name-sym", "get-public-key")

    def test_hsmauth_delete(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "delete-me",
            "-c",
            "123456",
            "-d",
            "password",
        )
        ykman_cli("hsmauth", "credentials", "delete", "delete-me", "-f")
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "delete-me" not in creds


class TestManagementKey:
    def test_change_management_key_prompt(self, ykman_cli):
        ykman_cli("hsmauth", "access", "change", input=NON_DEFAULT_MANAGEMENT_KEY)

        with pytest.raises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                "hsmauth",
                "access",
                "change",
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-n",
                DEFAULT_MANAGEMENT_KEY,
            )

        # Should succeed
        ykman_cli(
            "hsmauth",
            "access",
            "change",
            "-m",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-n",
            DEFAULT_MANAGEMENT_KEY,
        )

    def test_change_management_key_generate(self, ykman_cli):
        output = ykman_cli("hsmauth", "access", "change", "-g").output

        assert re.match(
            r"^Generated management key: [a-f0-9]{16}", output, re.MULTILINE
        )


class TestHostChallenge:
    @condition.min_version(5, 6)
    def test_get_host_challenge_symmetric(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-sym",
            "-c",
            "123456",
            "-d",
            "password",
        )

        output = ykman_cli(
            "hsmauth", "credentials", "get-challenge", "test-name-sym"
        ).output

        print(output)

        assert re.match(r"^Challenge: [a-f0-9]{8}", output, re.MULTILINE)

    @condition.min_version(5, 6)
    def test_get_host_challenge_asymmetric(self, ykman_cli):
        ykman_cli(
            "hsmauth", "credentials", "add", "test-name-asym", "-c", "123456", "-g"
        )

        output = ykman_cli(
            "hsmauth", "credentials", "get-challenge", "test-name-asym"
        ).output

        assert re.match(r"^Challenge: [a-f0-9]{65}", output, re.MULTILINE)


class TestSessionKeys:
    def test_calculate_sessions_keys_symmetric(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "add",
            "test-name-sym",
            "-c",
            "123456",
            "-d",
            "password",
        )

        context = os.urandom(16).hex()
        output = ykman_cli(
            "hsmauth",
            "credentials",
            "calculate",
            "test-name-sym",
            "-c",
            "123456",
            "-C",
            context,
        ).output

        assert re.match(
            r"^S-ENC:  [a-f0-9]{32}\nS-MAC:  [a-f0-9]{32}\nS-RMAC: [a-f0-9]{32}",
            output,
            re.MULTILINE,
        )
