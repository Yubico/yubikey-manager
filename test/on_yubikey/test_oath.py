import unittest
from ykman.util import TRANSPORT
from .util import (DestructiveYubikeyTestCase, missing_mode, ykman_cli)


URI_HOTP_EXAMPLE = 'otpauth://hotp/Example:demo@example.com?' \
        'secret=JBSWY3DPK5XXE3DEJ5TE6QKUJA======&issuer=Example&counter=1'

URI_TOTP_EXAMPLE = (
        'otpauth://totp/ACME%20Co:john.doe@email.com?'
        'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co'
        '&algorithm=SHA1&digits=6&period=30')

URI_TOTP_EXAMPLE_B = (
        'otpauth://totp/ACME%20Co:john.doe.b@email.com?'
        'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co'
        '&algorithm=SHA1&digits=6&period=30')


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class TestOATH(DestructiveYubikeyTestCase):

    def test_oath_info(self):
        output = ykman_cli('oath', 'info')
        self.assertIn('version:', output)

    def test_oath_add_credential(self):
        ykman_cli('oath', 'add', 'test-name', 'abba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name', creds)

    def test_oath_add_credential_prompt(self):
        ykman_cli('oath', 'add', 'test-name-2', input='abba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name-2', creds)

    def test_oath_add_credential_with_space(self):
        ykman_cli('oath', 'add', 'test-name-space', 'ab ba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name-space', creds)

    def test_oath_hidden_cred(self):
        ykman_cli('oath', 'add', '_hidden:name', 'abba')
        creds = ykman_cli('oath', 'code')
        self.assertNotIn('_hidden:name', creds)
        creds = ykman_cli('oath', 'code', '-H')
        self.assertIn('_hidden:name', creds)

    def test_oath_add_uri_hotp(self):
        ykman_cli('oath', 'uri', URI_HOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        self.assertIn('Example:demo', creds)

    def test_oath_add_uri_totp(self):
        ykman_cli('oath', 'uri', URI_TOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        self.assertIn('john.doe', creds)

    def test_oath_add_uri_totp_prompt(self):
        ykman_cli('oath', 'uri', input=URI_TOTP_EXAMPLE_B)
        creds = ykman_cli('oath', 'list')
        self.assertIn('john.doe', creds)

    def test_oath_code(self):
        ykman_cli('oath', 'add', 'test-name2', 'abba')
        creds = ykman_cli('oath', 'code')
        self.assertIn('test-name2', creds)

    def test_oath_code_query(self):
        ykman_cli('oath', 'add', 'query-me', 'abba')
        creds = ykman_cli('oath', 'code', 'query-me')
        self.assertIn('query-me', creds)

    def test_oath_reset(self):
        output = ykman_cli('oath', 'reset', '-f')
        self.assertIn('Success! All OATH credentials have been cleared from '
                      'your YubiKey', output)

    def test_oath_hotp_code(self):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'hotp-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'hotp-cred')
        self.assertIn('659165', cred)

    def test_oath_hotp_steam_code(self):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'Steam:steam-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'steam-cred')
        self.assertIn('CGC3K', cred)

    def test_oath_delete(self):
        ykman_cli('oath', 'add', 'delete-me', 'abba')
        ykman_cli('oath', 'delete', 'delete-me', '-f')
        self.assertNotIn('delete-me', ykman_cli('oath', 'list'))
