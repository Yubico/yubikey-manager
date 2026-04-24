from yubikit.hsmauth import (
    _parse_credential_password,
)


class TestHsmAuthFunctions:
    def test_parse_credential_password(self):
        parsed_credential_password = _parse_credential_password("123456")

        assert (
            b"123456\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            == parsed_credential_password
        )
