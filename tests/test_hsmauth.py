from ykman.hsmauth import generate_random_management_key

from yubikit.hsmauth import (
    _parse_credential_password,
    _parse_label,
    _password_to_key,
    CREDENTIAL_PASSWORD_LEN,
    MAX_LABEL_LEN,
)
from binascii import a2b_hex

import pytest


class TestHsmAuthFunctions:
    def test_generate_random_management_key(self):
        output1 = generate_random_management_key()
        output2 = generate_random_management_key()

        assert isinstance(output1, bytes)
        assert isinstance(output2, bytes)
        assert 16 == len(output1) == len(output2)

    def test_parse_credential_password(self):
        parsed_credential_password = _parse_credential_password("123456")

        assert (
            b"123456\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            == parsed_credential_password
        )

    def test_parse_credential_password_wrong_length(self):
        with pytest.raises(ValueError):
            _parse_credential_password(b"1" * (CREDENTIAL_PASSWORD_LEN + 1))

    def test_parse_label(self):
        parsed_label = _parse_label("Default key")

        assert isinstance(parsed_label, bytes)

    def test_parse_label_wrong_length(self):
        with pytest.raises(ValueError):
            _parse_label("1" * (MAX_LABEL_LEN + 1))

        with pytest.raises(ValueError):
            _parse_label("")

    def test_password_to_key(self):
        assert (
            a2b_hex("090b47dbed595654901dee1cc655e420"),
            a2b_hex("592fd483f759e29909a04c4505d2ce0a"),
        ) == _password_to_key("password")

    def test__password_to_key_utf8(self):
        assert (
            a2b_hex("f320972c667ba5cd4d35119a6b0271a1"),
            a2b_hex("f10050ca688e5a6ce62b1ffb0f6f6869"),
        ) == _password_to_key("κόσμε")

    def test_password_to_key_bytes_fails(self):
        with pytest.raises(AttributeError):
            _password_to_key(b"password")

        with pytest.raises(AttributeError):
            _password_to_key(a2b_hex("cebae1bdb9cf83cebcceb5"))
