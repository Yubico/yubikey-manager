# -*- coding: utf-8 -*-

import pytest
from .framework import yubikey_conditions


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

URI_TOTP_EXAMPLE_EXTRA_PARAMETER = (
        'otpauth://totp/ACME%20Co:john.doe.extra@email.com?'
        'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co'
        '&algorithm=SHA1&digits=6&period=30&skid=JKS3424d')

PASSWORD = 'aaaa'


class TestOATH(object):

    @pytest.fixture(autouse=True)
    def setUpTearDown(self, ykman_cli):
        ykman_cli('oath', 'reset', '-f')
        yield None
        ykman_cli('oath', 'reset', '-f')

    def test_oath_info(self, ykman_cli):
        output = ykman_cli('oath', 'info')
        assert 'version:' in output

    @yubikey_conditions.is_not_fips
    def test_info_does_not_indicate_fips_mode_for_non_fips_key(self, ykman_cli):
        info = ykman_cli('oath', 'info')
        assert 'FIPS:' not in info

    def test_oath_add_credential(self, ykman_cli):
        ykman_cli('oath', 'add', 'test-name', 'abba')
        creds = ykman_cli('oath', 'list')
        assert 'test-name' in creds

    def test_oath_add_credential_prompt(self, ykman_cli):
        ykman_cli('oath', 'add', 'test-name-2', input='abba')
        creds = ykman_cli('oath', 'list')
        assert 'test-name-2' in creds

    def test_oath_add_credential_with_space(self, ykman_cli):
        ykman_cli('oath', 'add', 'test-name-space', 'ab ba')
        creds = ykman_cli('oath', 'list')
        assert 'test-name-space' in creds

    def test_oath_hidden_cred(self, ykman_cli):
        ykman_cli('oath', 'add', '_hidden:name', 'abba')
        creds = ykman_cli('oath', 'code')
        assert '_hidden:name' not in creds
        creds = ykman_cli('oath', 'code', '-H')
        assert '_hidden:name' in creds

    def test_oath_add_uri_hotp(self, ykman_cli):
        ykman_cli('oath', 'uri', URI_HOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        assert 'Example:demo' in creds

    def test_oath_add_uri_totp(self, ykman_cli):
        ykman_cli('oath', 'uri', URI_TOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        assert 'john.doe' in creds

    def test_oath_add_uri_totp_extra_parameter(self, ykman_cli):
        ykman_cli('oath', 'uri', URI_TOTP_EXAMPLE_EXTRA_PARAMETER)
        creds = ykman_cli('oath', 'list')
        assert 'john.doe.extra' in creds

    def test_oath_add_uri_totp_prompt(self, ykman_cli):
        ykman_cli('oath', 'uri', input=URI_TOTP_EXAMPLE_B)
        creds = ykman_cli('oath', 'list')
        assert 'john.doe' in creds

    def test_oath_code(self, ykman_cli):
        ykman_cli('oath', 'add', 'test-name2', 'abba')
        creds = ykman_cli('oath', 'code')
        assert 'test-name2' in creds

    def test_oath_code_query(self, ykman_cli):
        ykman_cli('oath', 'add', 'query-me', 'abba')
        creds = ykman_cli('oath', 'code', 'query-me')
        assert 'query-me' in creds

    def test_oath_reset(self, ykman_cli):
        output = ykman_cli('oath', 'reset', '-f')
        assert('Success! All OATH credentials have been cleared '
               'from your YubiKey' in output)

    def test_oath_hotp_code(self, ykman_cli):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'hotp-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'hotp-cred')
        assert '659165' in cred

    def test_oath_hotp_steam_code(self, ykman_cli):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'Steam:steam-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'steam-cred')
        assert 'CGC3K' in cred

    def test_oath_delete(self, ykman_cli):
        ykman_cli('oath', 'add', 'delete-me', 'abba')
        ykman_cli('oath', 'delete', 'delete-me', '-f')
        assert 'delete-me', ykman_cli('oath' not in 'list')

    def test_oath_unicode(self, ykman_cli):
        ykman_cli('oath', 'add', '😃', 'abba')
        ykman_cli('oath', 'code')
        ykman_cli('oath', 'list')
        ykman_cli('oath', 'delete', '😃', '-f')

    @yubikey_conditions.is_not_fips
    @yubikey_conditions.version_min((4, 3, 1))
    def test_oath_sha512(self, ykman_cli):
        ykman_cli('oath', 'add', 'abba', 'abba', '--algorithm', 'SHA512')
        ykman_cli('oath', 'delete', 'abba', '-f')

    # NEO credential capacity may vary based on configuration
    @yubikey_conditions.version_min((4, 0, 0))
    def test_add_32_creds(self, ykman_cli):
        for i in range(32):
            ykman_cli('oath', 'add', 'test' + str(i), 'abba')
            output = ykman_cli('oath', 'list')
            lines = output.strip().split('\n')
            assert len(lines) == i + 1

        with pytest.raises(SystemExit):
            ykman_cli('oath', 'add', 'testx', 'abba')


@yubikey_conditions.is_fips
class TestOathFips(object):

    @pytest.fixture(autouse=True)
    def setUpTearDown(self, ykman_cli):
        ykman_cli('oath', 'reset', '-f')
        yield None
        ykman_cli('oath', 'reset', '-f')

    def test_no_fips_mode_without_password(self, ykman_cli):
        output = ykman_cli('oath', 'info')
        assert 'FIPS Approved Mode: No' in output

    def test_fips_mode_with_password(self, ykman_cli):
        ykman_cli('oath', 'set-password', '-n', PASSWORD)
        output = ykman_cli('oath', 'info')
        assert 'FIPS Approved Mode: Yes' in output

    def test_sha512_not_supported(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli('oath', 'add', 'abba', 'abba',
                      '--algorithm', 'SHA512')
