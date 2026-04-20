from ykman.hsmauth import generate_random_management_key
from yubikit.hsmauth import (
    _parse_credential_password,
)


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
