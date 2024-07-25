from ykman.piv import (
    generate_random_management_key,
    parse_rfc4514_string,
    generate_chuid,
)

from yubikit.core import NotSupportedError, Version
from yubikit.piv import (
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    PIN_POLICY,
    TOUCH_POLICY,
    _do_check_key_support,
    FascN,
    Chuid,
)
from datetime import date

import pytest


@pytest.mark.parametrize(
    "value",
    [
        r"UID=jsmith,DC=example,DC=net",
        r"OU=Sales+CN=J.  Smith,DC=example,DC=net",
        r"CN=James \"Jim\" Smith\, III,DC=example,DC=net",
        r"CN=Before\0dAfter,DC=example,DC=net",
        r"1.3.6.1.4.1.1466.0=#04024869",
        r"CN=Lu\C4\8Di\C4\87",
        r"1.2.840.113549.1.9.1=user@example.com",
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
            _do_check_key_support(
                Version(3, 1, 1),
                KEY_TYPE.ECCP384,
                PIN_POLICY.DEFAULT,
                TOUCH_POLICY.DEFAULT,
            )

        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(4, 4, 1),
                KEY_TYPE.RSA1024,
                PIN_POLICY.DEFAULT,
                TOUCH_POLICY.DEFAULT,
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.X25519):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(5, 7, 0),
                    key_type,
                    PIN_POLICY.DEFAULT,
                    TOUCH_POLICY.DEFAULT,
                    fips_restrictions=True,
                )

        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(5, 7, 0),
                KEY_TYPE.RSA2048,
                PIN_POLICY.NEVER,
                TOUCH_POLICY.DEFAULT,
                fips_restrictions=True,
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.RSA2048):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(4, 3, 4), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(5, 6, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in KEY_TYPE:
            _do_check_key_support(
                Version(5, 7, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )


def test_fascn():
    fascn = FascN(
        agency_code=32,
        system_code=1,
        credential_number=92446,
        credential_series=0,
        individual_credential_issue=1,
        person_identifier=1112223333,
        organizational_category=1,
        organizational_identifier=1223,
        organization_association_category=2,
    )

    # https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf
    # page 32
    expected = bytes.fromhex("D0439458210C2C19A0846D83685A1082108CE73984108CA3FC")
    assert bytes(fascn) == expected

    assert FascN.from_bytes(expected) == fascn


def test_chuid():
    guid = b"x" * 16
    chuid = Chuid(
        # Non-Federal Issuer FASC-N
        fasc_n=FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1),
        guid=guid,
        expiration_date=date(2030, 1, 1),
        asymmetric_signature=b"",
    )

    expected = bytes.fromhex(
        "3019d4e739da739ced39ce739d836858210842108421c84210c3eb3410787878787878787878"
        "78787878787878350832303330303130313e00fe00"
    )

    assert bytes(chuid) == expected

    assert Chuid.from_bytes(expected) == chuid


def test_chuid_deserialize():
    chuid = Chuid(
        buffer_length=123,
        fasc_n=FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1),
        agency_code=b"1234",
        organizational_identifier=b"5678",
        duns=b"123456789",
        guid=b"x" * 16,
        expiration_date=date(2030, 1, 1),
        authentication_key_map=b"1234567890",
        asymmetric_signature=b"0987654321",
        lrc=255,
    )

    assert Chuid.from_bytes(bytes(chuid)) == chuid


def test_chuid_generate():
    chuid = Chuid.from_bytes(generate_chuid())
    assert chuid.expiration_date == date(2030, 1, 1)
    assert chuid.fasc_n.agency_code == 9999
