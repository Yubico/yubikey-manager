#  vim: set fileencoding=utf-8 :

from yubikit.oath import (
    CredentialData,
    OATH_TYPE,
    HASH_ALGORITHM,
    _derive_key,
    _parse_cred_id,
    _format_cred_id,
)
import unittest


class TestOathFunctions(unittest.TestCase):
    def test_credential_parse_period_and_issuer_and_name(self):
        issuer, name, period = _parse_cred_id(b"20/Issuer:name", OATH_TYPE.TOTP)
        self.assertEqual(20, period)
        self.assertEqual("Issuer", issuer)
        self.assertEqual("name", name)

    def test_credential_parse_weird_issuer_and_name(self):
        issuer, name, period = _parse_cred_id(b"weird/Issuer:name", OATH_TYPE.TOTP)
        self.assertEqual(30, period)
        self.assertEqual("weird/Issuer", issuer)
        self.assertEqual("name", name)

    def test_credential_parse_issuer_and_name(self):
        issuer, name, period = _parse_cred_id(b"Issuer:name", OATH_TYPE.TOTP)
        self.assertEqual(30, period)
        self.assertEqual("Issuer", issuer)
        self.assertEqual("name", name)

    def test_credential_parse_period_and_name(self):
        issuer, name, period = _parse_cred_id(b"20/name", OATH_TYPE.TOTP)
        self.assertEqual(20, period)
        self.assertIsNone(issuer)
        self.assertEqual("name", name)

    def test_credential_parse_only_name(self):
        issuer, name, period = _parse_cred_id(b"name", OATH_TYPE.TOTP)
        self.assertEqual(30, period)
        self.assertIsNone(issuer)
        self.assertEqual("name", name)

    def test_credential_data_make_key(self):
        self.assertEqual(b"name", _format_cred_id(None, "name", OATH_TYPE.TOTP))
        self.assertEqual(
            b"Issuer:name", _format_cred_id("Issuer", "name", OATH_TYPE.TOTP)
        )
        self.assertEqual(
            b"20/Issuer:name",
            _format_cred_id("Issuer", "name", OATH_TYPE.TOTP, period=20),
        )
        self.assertEqual(
            b"Issuer:name", _format_cred_id("Issuer", "name", OATH_TYPE.TOTP, period=30)
        )
        self.assertEqual(
            b"20/name", _format_cred_id(None, "name", OATH_TYPE.TOTP, period=20)
        )

    def test_derive_key(self):
        self.assertEqual(
            b"\xb0}\xa1\xe7\xde\x87\xf8\x9a\x87\xa2\xb5\x98\xea\xa2\x18\x8c",
            _derive_key(b"\0\0\0\0\0\0\0\0", u"foobar"),
        )
        self.assertEqual(
            b"\xda\x81\x8ek,\xf0\xa2\xd0\xbf\x19\xb3\xdd\xd3K\x83\xf5",
            _derive_key(b"12345678", u"Hallå världen!"),
        )
        self.assertEqual(
            b"\xf3\xdf\xa7\x81T\xc8\x102\x99E\xfb\xc4\xb55\xe57",
            _derive_key(b"saltsalt", u"Ťᶒśƫ ᵽĥřӓşḛ"),
        )

    def test_parse_uri_issuer(self):
        no_issuer = CredentialData.parse_uri("otpauth://totp/account" "?secret=abba")
        self.assertIsNone(no_issuer.issuer)

        from_param = CredentialData.parse_uri(
            "otpauth://totp/account" "?secret=abba&issuer=Test"
        )
        self.assertEqual("Test", from_param.issuer)

        from_name = CredentialData.parse_uri(
            "otpauth://totp/Test:account" "?secret=abba"
        )
        self.assertEqual("Test", from_name.issuer)

        with_both = CredentialData.parse_uri(
            "otpauth://totp/TestA:account" "?secret=abba&issuer=TestB"
        )
        self.assertEqual("TestB", with_both.issuer)

    def test_parse_uri(self):
        data = CredentialData.parse_uri(
            "otpauth://totp/Issuer:account"
            "?secret=abba&issuer=Issuer"
            "&algorithm=SHA256&digits=7"
            "&period=20&counter=5"
        )
        self.assertEqual(b"\0B", data.secret)
        self.assertEqual("Issuer", data.issuer)
        self.assertEqual("account", data.name)
        self.assertEqual(OATH_TYPE.TOTP, data.oath_type)
        self.assertEqual(HASH_ALGORITHM.SHA256, data.hash_algorithm)
        self.assertEqual(7, data.digits)
        self.assertEqual(20, data.period)
        self.assertEqual(5, data.counter)
