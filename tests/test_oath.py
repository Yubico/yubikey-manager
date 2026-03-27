#  vim: set fileencoding=utf-8 :

import pytest

from yubikit.oath import (
    HASH_ALGORITHM,
    OATH_TYPE,
    CredentialData,
)


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("otpauth://totp/account?secret=abba", None),
        ("otpauth://totp/account?secret=abba&issuer=Test", "Test"),
        ("otpauth://totp/Test:account?secret=abba", "Test"),
        ("otpauth://totp/TestA:account?secret=abba&issuer=TestB", "TestB"),
    ],
)
def test_parse_uri_issuer(uri, expected):
    assert CredentialData.parse_uri(uri).issuer == expected


def test_parse_uri_full_payload():
    data = CredentialData.parse_uri(
        "otpauth://totp/Issuer:account"
        "?secret=abba&issuer=Issuer"
        "&algorithm=SHA256&digits=7"
        "&period=20&counter=5"
    )
    assert data.secret == b"\0B"
    assert data.issuer == "Issuer"
    assert data.name == "account"
    assert data.oath_type == OATH_TYPE.TOTP
    assert data.hash_algorithm == HASH_ALGORITHM.SHA256
    assert data.digits == 7
    assert data.period == 20
    assert data.counter == 5
