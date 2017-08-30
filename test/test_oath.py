from ykman.oath import Credential
import unittest


class TestOathFunctions(unittest.TestCase):

    def test_credential_parse_period_and_issuer_and_name(self):
        period, issuer, name = Credential.parse_name('20/Issuer:name')
        self.assertEqual(20, period)
        self.assertEqual('Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_issuer_and_name(self):
        period, issuer, name = Credential.parse_name('Issuer:name')
        self.assertEqual(30, period)
        self.assertEqual('Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_period_and_name(self):
        period, issuer, name = Credential.parse_name('20/name')
        self.assertEqual(20, period)
        self.assertEqual(None, issuer)
        self.assertEqual('name', name)

    def test_credential_parse_only_name(self):
        period, issuer, name = Credential.parse_name('name')
        self.assertEqual(30, period)
        self.assertEqual(None, issuer)
        self.assertEqual('name', name)

    def test_credential_serialize_name(self):
        self.assertEqual('name', Credential.serialize_name('name'))
        self.assertEqual(
            'Issuer:name', Credential.serialize_name('name', issuer='Issuer'))
        self.assertEqual(
            '20/Issuer:name', Credential.serialize_name(
                'name', issuer='Issuer', period=20))
        self.assertEqual(
            'Issuer:name', Credential.serialize_name(
                'name', issuer='Issuer', period=30))
        self.assertEqual(
            '20/name', Credential.serialize_name('name', period=20))

    def test_credential_expiration(self):
        cred = Credential('name')
        cred.update_expiration(0)
        self.assertEqual(30, cred.expiration)
        cred.update_expiration(30)
        self.assertEqual(60, cred.expiration)
        cred.update_expiration(60)
        self.assertEqual(90, cred.expiration)
