from ykman.piv import generate_random_management_key, parse_rfc4514_string

from yubikit.core import NotSupportedError
from yubikit.piv import (
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    PIN_POLICY,
    TOUCH_POLICY,
    check_key_support,
)

import pytest


@pytest.mark.parametrize(
    "value",
    [
        r"UID=jsmith,DC=example,DC=net",
        r"OU=Sales+CN=J.  Smith,DC=example,DC=net",
        r"CN=James \"Jim\" Smith\, III,DC=example,DC=net",
        r"CN=Before\0dAfter,DC=example,DC=net",
        # r"1.3.6.1.4.1.1466.0=#04024869", - Not supported.
        r"CN=Lu\C4\8Di\C4\87",
    ],
)
def test_parse_rfc4514_string(value):
    name = parse_rfc4514_string(value)
    name2 = parse_rfc4514_string(name.rfc4514_string())
    assert name == name2


class TestPivFunctions:
    def test_generate_random_management_key(self):
        output1 = generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES)
        output2 = generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES)
        assert isinstance(output1, bytes)
        assert isinstance(output2, bytes)
        assert output1 != output2

        assert 24 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES))

        assert 16 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES128))
        assert 24 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES192))
        assert 32 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES256))

    def test_supported_algorithms(self):
        with pytest.raises(NotSupportedError):
            check_key_support(
                (3, 1, 1), KEY_TYPE.ECCP384, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )

        with pytest.raises(NotSupportedError):
            check_key_support(
                (4, 4, 1), KEY_TYPE.RSA1024, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.RSA2048):
            with pytest.raises(NotSupportedError):
                check_key_support(
                    (4, 3, 4), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in KEY_TYPE:
            check_key_support(
                (5, 1, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )
