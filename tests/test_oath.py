#  vim: set fileencoding=utf-8 :

import pytest

from yubikit.oath import (
    HASH_ALGORITHM,
    OATH_TYPE,
    CredentialData,
    _derive_key,
    _format_cred_id,
    _parse_cred_id,
)


@pytest.mark.parametrize(
    ("raw", "issuer", "name", "period"),
    [
        (b"20/Issuer:name", "Issuer", "name", 20),
        (b"weird/Issuer:name", "weird/Issuer", "name", 30),
        (b"Issuer:name", "Issuer", "name", 30),
        (b"20/name", None, "name", 20),
        (b"name", None, "name", 30),
    ],
)
def test_parse_cred_id(raw, issuer, name, period):
    parsed_issuer, parsed_name, parsed_period = _parse_cred_id(raw, OATH_TYPE.TOTP)
    assert (parsed_issuer, parsed_name, parsed_period) == (issuer, name, period)


@pytest.mark.parametrize(
    ("issuer", "name", "period", "expected"),
    [
        (None, "name", None, b"name"),
        ("Issuer", "name", None, b"Issuer:name"),
        ("Issuer", "name", 20, b"20/Issuer:name"),
        ("Issuer", "name", 30, b"Issuer:name"),
        (None, "name", 20, b"20/name"),
    ],
)
def test_format_cred_id(issuer, name, period, expected):
    kwargs = {}
    if period is not None:
        kwargs["period"] = period
    assert _format_cred_id(issuer, name, OATH_TYPE.TOTP, **kwargs) == expected


@pytest.mark.parametrize(
    ("salt", "password", "expected"),
    [
        (
            b"\0" * 8,
            "foobar",
            b"\xb0}\xa1\xe7\xde\x87\xf8\x9a\x87\xa2\xb5\x98\xea\xa2\x18\x8c",
        ),
        (
            b"12345678",
            "Hallå världen!",
            b"\xda\x81\x8ek,\xf0\xa2\xd0\xbf\x19\xb3\xdd\xd3K\x83\xf5",
        ),
        (
            b"saltsalt",
            "Ťᶒśƫ ᵽĥřӓşḛ",
            b"\xf3\xdf\xa7\x81T\xc8\x102\x99E\xfb\xc4\xb55\xe57",
        ),
    ],
)
def test_derive_key(salt, password, expected):
    assert _derive_key(salt, password) == expected


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
