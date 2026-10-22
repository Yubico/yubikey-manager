from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from yubikit.hsmauth import (
    HsmAuthSession,
    _parse_credential_password,
)


class TestHsmAuthFunctions:
    def test_parse_credential_password(self):
        parsed_credential_password = _parse_credential_password("123456")

        assert (
            b"123456\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            == parsed_credential_password
        )

    @pytest.mark.parametrize(
        "password",
        ["", "a" * 15, "a" * 16, "\u00e9" * 8, "\U0001f511" * 4, "a\0b"],
    )
    def test_parse_string_password(self, password):
        assert _parse_credential_password(password) == password.encode().ljust(
            16, b"\0"
        )

    @pytest.mark.parametrize("password", [bytes(16), bytes(range(16)), b"\xff" * 16])
    def test_parse_bytes_password(self, password):
        assert _parse_credential_password(password) == password

    @pytest.mark.parametrize(
        "password",
        ["a" * 17, "a" * 15 + "\u00e9", "\u00e9" * 8 + "a", "\U0001f511" * 4 + "a"],
    )
    def test_reject_long_string_password(self, password):
        with pytest.raises(ValueError, match="at most 16 UTF-8 bytes"):
            _parse_credential_password(password)

    @pytest.mark.parametrize("length", [0, 1, 15, 17, 32])
    def test_reject_wrong_length_bytes_password(self, length):
        with pytest.raises(ValueError, match="16 bytes"):
            _parse_credential_password(bytes(length))

    @pytest.mark.parametrize(
        "password",
        [
            0,
            16,
            -1,
            True,
            False,
            None,
            1.5,
            [0] * 16,
            bytearray(16),
            memoryview(bytes(16)),
        ],
    )
    def test_reject_wrong_password_type(self, password):
        with pytest.raises(TypeError, match="bytes or str"):
            _parse_credential_password(password)


@pytest.fixture
def session(monkeypatch):
    native = Mock(version=(6, 0, 0))
    monkeypatch.setattr("yubikit.hsmauth._NativeHsmAuthSession", lambda *args: native)
    return HsmAuthSession(Mock(_session=None)), native


@pytest.mark.parametrize(
    ("method", "arguments", "password_argument"),
    [
        (
            "put_credential_symmetric",
            dict(
                management_key=bytes(16),
                label="test",
                key_enc=bytes(16),
                key_mac=bytes(16),
            ),
            "credential_password",
        ),
        (
            "put_credential_derived",
            dict(management_key=bytes(16), label="test", derivation_password="d" * 40),
            "credential_password",
        ),
        (
            "put_credential_asymmetric",
            dict(management_key=bytes(16), label="test"),
            "credential_password",
        ),
        (
            "generate_credential_asymmetric",
            dict(management_key=bytes(16), label="test"),
            "credential_password",
        ),
        (
            "change_credential_password",
            dict(label="test", new_credential_password="new"),
            "credential_password",
        ),
        (
            "change_credential_password",
            dict(label="test", credential_password="current"),
            "new_credential_password",
        ),
        (
            "change_credential_password_admin",
            dict(management_key=bytes(16), label="test"),
            "new_credential_password",
        ),
        (
            "calculate_session_keys_symmetric",
            dict(label="test", context=bytes(16)),
            "credential_password",
        ),
        (
            "calculate_session_keys_asymmetric",
            dict(label="test", context=bytes(130), card_crypto=bytes(16)),
            "credential_password",
        ),
        ("get_challenge", dict(label="test"), "credential_password"),
    ],
)
@pytest.mark.parametrize(
    ("password", "error"),
    [
        (16, TypeError),
        (True, TypeError),
        ("a" * 17, ValueError),
        ("a" * 15 + "\u00e9", ValueError),
        (bytes(17), ValueError),
    ],
)
def test_invalid_password_never_reaches_native(
    session, method, arguments, password_argument, password, error
):
    session, native = session
    arguments = dict(arguments, **{password_argument: password})
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    if method == "put_credential_asymmetric":
        arguments["private_key"] = private_key
    elif method == "calculate_session_keys_asymmetric":
        arguments["public_key"] = private_key.public_key()
    with pytest.raises(error):
        getattr(session, method)(**arguments)
    assert native.mock_calls == []


def test_get_challenge_without_password(session):
    session, native = session
    native.get_challenge.return_value = b"challenge"
    assert session.get_challenge("test") == b"challenge"
    native.get_challenge.assert_called_once_with("test", None)
