# -*- coding: utf-8 -*-
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yubikit.management import CAPABILITY
from yubikit.hsmauth import (
    TAG_LABEL,
    TAG_CONTEXT,
    TAG_CREDENTIAL_PASSWORD,
    INS_CALCULATE,
    _parse_label,
    _parse_credential_password,
)
from yubikit.core import Tlv
from .. import condition

import pytest
import re
import os
import tempfile
import struct

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


@pytest.fixture()
def tmp_file():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    yield tmp
    tmp.close()
    os.remove(tmp.name)


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.HSMAUTH)
@condition.min_version(5, 4, 3)
def preconditions(ykman_cli):
    ykman_cli("hsmauth", "reset", "-f")


class TestHsmAuth:
    def test_hsmauth_info(self, ykman_cli):
        output = ykman_cli("hsmauth", "info").output
        assert "version:" in output

    def test_hsmauth_reset(self, ykman_cli):
        output = ykman_cli("hsmauth", "reset", "-f").output
        assert (
            "Success! All YubiHSM Auth data have been cleared from the YubiKey."
            in output
        )


def calculate_session_keys_apdu(label, context, credential_password):
    data = (
        Tlv(TAG_LABEL, _parse_label(label))
        + Tlv(TAG_CONTEXT, context)
        + Tlv(TAG_CREDENTIAL_PASSWORD, _parse_credential_password(credential_password))
    )

    apdu = struct.pack("<BBBB", 0, INS_CALCULATE, 0, 0).hex()
    apdu = apdu + ":" + data.hex() + "=9000"

    return apdu


class TestCredentials:
    def verify_credential_password(self, ykman_cli, credential_password, label):
        context = b"g\xfc\xf1\xfe\xb5\xf1\xd8\x83\xedv=\xbfI0\x90\xbb"
        apdu = calculate_session_keys_apdu(label, context, credential_password)

        # Try to calculate session keys using credential password
        ykman_cli("apdu", "-a", "hsmauth", apdu)

    def test_import_credential_symmetric(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "symmetric",
            "test-name-sym",
            "-c",
            "123456",
            "-E",
            os.urandom(16).hex(),
            "-M",
            os.urandom(16).hex(),
            "-m",
            DEFAULT_MANAGEMENT_KEY,
        )
        self.verify_credential_password(ykman_cli, "123456", "test-name-sym")
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name-sym" in creds

    def test_import_credential_symmetric_generate(self, ykman_cli):
        output = ykman_cli(
            "hsmauth",
            "credentials",
            "symmetric",
            "test-name-sym-gen",
            "-c",
            "123456",
            "-g",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
        ).output
        self.verify_credential_password(ykman_cli, "123456", "test-name-sym-gen")
        assert "Generated ENC and MAC keys" in output

    def test_import_credential_symmetric_derived(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "derive",
            "test-name-sym-derived",
            "-c",
            "123456",
            "-d",
            "password",
        )
        self.verify_credential_password(ykman_cli, "123456", "test-name-sym-derived")
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name-sym-derived" in creds

    @condition.min_version(5, 6)
    def test_import_credential_asymmetric(self, ykman_cli):
        pair = generate_pem_eccp256_keypair()
        ykman_cli(
            "hsmauth",
            "credentials",
            "import",
            "test-name-asym",
            "-c",
            "123456",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=pair[0],
        )
        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name-asym" in creds

        public_key_exported = ykman_cli(
            "hsmauth", "credentials", "export", "test-name-asym", "-"
        ).stdout_bytes
        assert pair[1] == public_key_exported

    @condition.min_version(5, 6)
    def test_generate_credential_asymmetric(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "generate",
            "test-name-asym-generated",
            "-c",
            "123456",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
        )

        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "test-name-asym-generated" in creds

    def test_import_credential_touch_required(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "derive",
            "test-name-touch",
            "-c",
            "123456",
            "-d",
            "password",
            "-t",
        )

        creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "On" in creds
        assert "test-name-touch" in creds

    @condition.min_version(5, 6)
    def test_export_public_key_to_file(self, ykman_cli, eccp256_keypair, tmp_file):
        private_key_file, public_key = eccp256_keypair
        ykman_cli(
            "hsmauth",
            "credentials",
            "import",
            "test-name-asym",
            "-c",
            "123456",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            private_key_file,
        )

        ykman_cli(
            "hsmauth",
            "credentials",
            "export",
            "test-name-asym",
            tmp_file.name,
        )

        public_key_from_file = tmp_file.read()
        assert public_key_from_file == public_key

    @condition.min_version(5, 6)
    def test_export_public_key_symmetric_credential(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "derive",
            "test-name-sym",
            "-c",
            "123456",
            "-d",
            "password",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
        )

        with pytest.raises(SystemExit):
            ykman_cli("hsmauth", "credentials", "export", "test-name-sym")

    def test_delete_credential(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "credentials",
            "derive",
            "delete-me",
            "-c",
            "123456",
            "-d",
            "password",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
        )
        old_creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "delete-me" in old_creds
        ykman_cli("hsmauth", "credentials", "delete", "delete-me", "-f")
        new_creds = ykman_cli("hsmauth", "credentials", "list").output
        assert "delete-me" not in new_creds


class TestManagementKey:
    def test_change_management_key(self, ykman_cli):
        ykman_cli(
            "hsmauth",
            "access",
            "change-management-key",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-n",
            NON_DEFAULT_MANAGEMENT_KEY,
        )

        with pytest.raises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                "hsmauth",
                "access",
                "change-management-key",
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-n",
                DEFAULT_MANAGEMENT_KEY,
            )

        # Should succeed
        ykman_cli(
            "hsmauth",
            "access",
            "change-management-key",
            "-m",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-n",
            DEFAULT_MANAGEMENT_KEY,
        )

    def test_change_management_key_generate(self, ykman_cli):
        output = ykman_cli(
            "hsmauth",
            "access",
            "change-management-key",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-g",
        ).output

        assert re.match(
            r"^Generated management key: [a-f0-9]{16}", output, re.MULTILINE
        )
