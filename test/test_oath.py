#  vim: set fileencoding=utf-8 :

from ykman.oath import Credential, CredentialData, _derive_key, OATH_TYPE, ALGO
import unittest


class TestOathFunctions(unittest.TestCase):

    def test_credential_parse_period_and_issuer_and_name(self):
        issuer, name, period = Credential.parse_key(b'20/Issuer:name')
        self.assertEqual(20, period)
        self.assertEqual('Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_wierd_issuer_and_name(self):
        issuer, name, period = Credential.parse_key(b'wierd/Issuer:name')
        self.assertEqual(30, period)
        self.assertEqual('wierd/Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_issuer_and_name(self):
        issuer, name, period = Credential.parse_key(b'Issuer:name')
        self.assertEqual(30, period)
        self.assertEqual('Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_period_and_name(self):
        issuer, name, period = Credential.parse_key(b'20/name')
        self.assertEqual(20, period)
        self.assertIsNone(issuer)
        self.assertEqual('name', name)

    def test_credential_parse_only_name(self):
        issuer, name, period = Credential.parse_key(b'name')
        self.assertEqual(30, period)
        self.assertIsNone(issuer)
        self.assertEqual('name', name)

    def test_credential_data_make_key(self):
        self.assertEqual(b'name', CredentialData(b'', None, 'name').make_key())
        self.assertEqual(b'Issuer:name',
                         CredentialData(b'', 'Issuer', 'name').make_key())
        self.assertEqual(b'20/Issuer:name',
                         CredentialData(b'', 'Issuer', 'name', period=20
                                        ).make_key())
        self.assertEqual(b'Issuer:name',
                         CredentialData(b'', 'Issuer', 'name', period=30
                                        ).make_key())
        self.assertEqual(b'20/name',
                         CredentialData(b'', None, 'name', period=20
                                        ).make_key())

    def test_derive_key(self):
        self.assertEqual(
            b'\xb0}\xa1\xe7\xde\x87\xf8\x9a\x87\xa2\xb5\x98\xea\xa2\x18\x8c',
            _derive_key(b'\0\0\0\0\0\0\0\0', u'foobar'))
        self.assertEqual(
            b'\xda\x81\x8ek,\xf0\xa2\xd0\xbf\x19\xb3\xdd\xd3K\x83\xf5',
            _derive_key(b'12345678', u'Hallå världen!'))
        self.assertEqual(
            b'\xf3\xdf\xa7\x81T\xc8\x102\x99E\xfb\xc4\xb55\xe57',
            _derive_key(b'saltsalt', u'Ťᶒśƫ ᵽĥřӓşḛ'))

    def test_parse_uri_issuer(self):
        no_issuer = CredentialData.from_uri('otpauth://totp/account'
                                            '?secret=abba')
        self.assertIsNone(no_issuer.issuer)

        from_param = CredentialData.from_uri('otpauth://totp/account'
                                             '?secret=abba&issuer=Test')
        self.assertEqual('Test', from_param.issuer)

        from_name = CredentialData.from_uri('otpauth://totp/Test:account'
                                            '?secret=abba')
        self.assertEqual('Test', from_name.issuer)

        with_both = CredentialData.from_uri('otpauth://totp/TestA:account'
                                            '?secret=abba&issuer=TestB')
        self.assertEqual('TestB', with_both.issuer)

    def test_parse_uri(self):
        data = CredentialData.from_uri('otpauth://totp/Issuer:account'
                                       '?secret=abba&issuer=Issuer'
                                       '&algorithm=SHA256&digits=7'
                                       '&period=20&counter=5')
        self.assertEqual(b'\0B', data.secret)
        self.assertEqual('Issuer', data.issuer)
        self.assertEqual('account', data.name)
        self.assertEqual(OATH_TYPE.TOTP, data.oath_type)
        self.assertEqual(ALGO.SHA256, data.algorithm)
        self.assertEqual(7, data.digits)
        self.assertEqual(20, data.period)
        self.assertEqual(5, data.counter)
        self.assertEqual(False, data.touch)
