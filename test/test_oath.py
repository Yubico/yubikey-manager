from ykman.oath import Credential
import unittest


class TestOathFunctions(unittest.TestCase):

    def test_credential_parse_period_and_issuer_and_name(self):
        period, issuer, name = Credential.parse_long_name('20/Issuer:name')
        self.assertEqual(20, period)
        self.assertEqual('Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_wierd_issuer_and_name(self):
        period, issuer, name = Credential.parse_long_name('wierd/Issuer:name')
        self.assertEqual(30, period)
        self.assertEqual('wierd/Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_issuer_and_name(self):
        period, issuer, name = Credential.parse_long_name('Issuer:name')
        self.assertEqual(30, period)
        self.assertEqual('Issuer', issuer)
        self.assertEqual('name', name)

    def test_credential_parse_period_and_name(self):
        period, issuer, name = Credential.parse_long_name('20/name')
        self.assertEqual(20, period)
        self.assertEqual(None, issuer)
        self.assertEqual('name', name)

    def test_credential_parse_only_name(self):
        period, issuer, name = Credential.parse_long_name('name')
        self.assertEqual(30, period)
        self.assertEqual(None, issuer)
        self.assertEqual('name', name)

    def test_credential_serialize_name(self):
        self.assertEqual('name', Credential('name').long_name())
        self.assertEqual(
            'Issuer:name', Credential('name', issuer='Issuer').long_name())
        self.assertEqual(
            '20/Issuer:name', Credential(
                'name', issuer='Issuer', period=20).long_name())
        self.assertEqual(
            'Issuer:name', Credential(
                'name', issuer='Issuer', period=30).long_name())
        self.assertEqual(
            '20/name', Credential('name', period=20).long_name())

    def test_credential_expiration(self):
        cred = Credential('name')
        cred.update_expiration(0)
        self.assertEqual(30, cred.expiration)
        cred.update_expiration(30)
        self.assertEqual(60, cred.expiration)
        cred.update_expiration(60)
        self.assertEqual(90, cred.expiration)
