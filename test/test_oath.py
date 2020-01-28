#  vim: set fileencoding=utf-8 :

from ykman.oath import Credential, CredentialData, _derive_key, OATH_TYPE, ALGO


class TestOathFunctions(object):

    def test_credential_parse_period_and_issuer_and_name(self):
        issuer, name, period = Credential.parse_key(b'20/Issuer:name')
        assert 20 == period
        assert 'Issuer' == issuer
        assert 'name' == name

    def test_credential_parse_weird_issuer_and_name(self):
        issuer, name, period = Credential.parse_key(b'weird/Issuer:name')
        assert 30 == period
        assert 'weird/Issuer' == issuer
        assert 'name' == name

    def test_credential_parse_issuer_and_name(self):
        issuer, name, period = Credential.parse_key(b'Issuer:name')
        assert 30 == period
        assert 'Issuer' == issuer
        assert 'name' == name

    def test_credential_parse_period_and_name(self):
        issuer, name, period = Credential.parse_key(b'20/name')
        assert period == 20
        assert issuer is None
        assert 'name' == name

    def test_credential_parse_only_name(self):
        issuer, name, period = Credential.parse_key(b'name')
        assert period == 30
        assert issuer is None
        assert 'name' == name

    def test_credential_data_make_key(self):
        assert b'name' == CredentialData(b'', None, 'name').make_key()
        assert(b'Issuer:name'
               == CredentialData(b'', 'Issuer', 'name').make_key())
        assert(b'20/Issuer:name'
               == CredentialData(b'', 'Issuer', 'name', period=20).make_key())
        assert(b'Issuer:name'
               == CredentialData(b'', 'Issuer', 'name', period=30).make_key())
        assert(b'20/name'
               == CredentialData(b'', None, 'name', period=20).make_key())

    def test_derive_key(self):
        assert(
            b'\xb0}\xa1\xe7\xde\x87\xf8\x9a\x87\xa2\xb5\x98\xea\xa2\x18\x8c'
            ==
            _derive_key(b'\0\0\0\0\0\0\0\0', u'foobar'))
        assert(
            b'\xda\x81\x8ek,\xf0\xa2\xd0\xbf\x19\xb3\xdd\xd3K\x83\xf5'
            ==
            _derive_key(b'12345678', u'Hallå världen!'))
        assert(
            b'\xf3\xdf\xa7\x81T\xc8\x102\x99E\xfb\xc4\xb55\xe57'
            ==
            _derive_key(b'saltsalt', u'Ťᶒśƫ ᵽĥřӓşḛ'))

    def test_parse_uri_issuer(self):
        no_issuer = CredentialData.from_uri('otpauth://totp/account'
                                            '?secret=abba')
        assert no_issuer.issuer is None

        from_param = CredentialData.from_uri('otpauth://totp/account'
                                             '?secret=abba&issuer=Test')
        assert 'Test' == from_param.issuer

        from_name = CredentialData.from_uri('otpauth://totp/Test:account'
                                            '?secret=abba')
        assert 'Test' == from_name.issuer

        with_both = CredentialData.from_uri('otpauth://totp/TestA:account'
                                            '?secret=abba&issuer=TestB')
        assert 'TestB' == with_both.issuer

    def test_parse_uri(self):
        data = CredentialData.from_uri('otpauth://totp/Issuer:account'
                                       '?secret=abba&issuer=Issuer'
                                       '&algorithm=SHA256&digits=7'
                                       '&period=20&counter=5')
        assert b'\0B' == data.secret
        assert 'Issuer' == data.issuer
        assert 'account' == data.name
        assert OATH_TYPE.TOTP == data.oath_type
        assert ALGO.SHA256 == data.algorithm
        assert 7 == data.digits
        assert 20 == data.period
        assert 5 == data.counter
        assert not data.touch
