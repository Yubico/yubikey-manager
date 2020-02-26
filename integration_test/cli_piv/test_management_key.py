import re
import pytest

from .util import (
    old_new_new, DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY,
    NON_DEFAULT_MANAGEMENT_KEY)


class ManagementKey(object):

    @pytest.fixture(autouse=True, scope='class')
    def setUp(self, ykman_cli):
        ykman_cli('piv', 'reset', '-f')

    def test_change_management_key_force_fails_without_generate(self, ykman_cli):  # noqa: E501
        with pytest.raises(SystemExit):
            ykman_cli(
                'piv', 'change-management-key', '-P', DEFAULT_PIN,
                '-m', DEFAULT_MANAGEMENT_KEY, '-f')

    def test_change_management_key_protect_random(self, ykman_cli):
        ykman_cli(
            'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
            '-m', DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        assert('Management key is stored on the YubiKey, protected by PIN'
               in output)

        with pytest.raises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                '-m', DEFAULT_MANAGEMENT_KEY)

        # Should succeed - PIN as key
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN)

    def test_change_management_key_protect_prompt(self, ykman_cli):
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                  input=DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        assert('Management key is stored on the YubiKey, protected by PIN'
               in output)

        with pytest.raises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                '-m', DEFAULT_MANAGEMENT_KEY)

        # Should succeed - PIN as key
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN)

    def test_change_management_key_no_protect_generate(self, ykman_cli):
        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', DEFAULT_MANAGEMENT_KEY, '-g')
        assert(
            re.compile(r'^Generated management key: [a-f0-9]{48}$',
                       re.MULTILINE)
            .match(output))

        output = ykman_cli('piv', 'info')
        assert 'Management key is stored on the YubiKey' not in output

    def test_change_management_key_no_protect_arg(self, ykman_cli):
        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', DEFAULT_MANAGEMENT_KEY,
            '-n', NON_DEFAULT_MANAGEMENT_KEY)
        assert '' == output
        output = ykman_cli('piv', 'info')
        assert 'Management key is stored on the YubiKey' not in output

        with pytest.raises(SystemExit):
            ykman_cli(
                'piv', 'change-management-key',
                '-m', DEFAULT_MANAGEMENT_KEY,
                '-n', NON_DEFAULT_MANAGEMENT_KEY)

        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', NON_DEFAULT_MANAGEMENT_KEY,
            '-n', DEFAULT_MANAGEMENT_KEY)
        assert '' == output

    def test_change_management_key_no_protect_arg_bad_length(self, ykman_cli):
        with pytest.raises(SystemExit,
                           msg='Management key must be exactly '
                           '24 bytes long (48 hexadecimal digits).'):
            ykman_cli(
                'piv', 'change-management-key',
                '-m', DEFAULT_MANAGEMENT_KEY,
                '-n', '10020304050607080102030405060708')

    def test_change_management_key_no_protect_prompt(self, ykman_cli):
        output = ykman_cli('piv', 'change-management-key',
                           input=old_new_new(DEFAULT_MANAGEMENT_KEY,
                                             NON_DEFAULT_MANAGEMENT_KEY))
        assert 'Generated' not in output
        output = ykman_cli('piv', 'info')
        assert 'Management key is stored on the YubiKey' not in output

        with pytest.raises(SystemExit):
            ykman_cli('piv', 'change-management-key',
                      input=old_new_new(DEFAULT_MANAGEMENT_KEY,
                                        NON_DEFAULT_MANAGEMENT_KEY))

        ykman_cli('piv', 'change-management-key',
                  input=old_new_new(NON_DEFAULT_MANAGEMENT_KEY,
                                    DEFAULT_MANAGEMENT_KEY))
        assert 'Generated' not in output

    def test_change_management_key_new_key_conflicts_with_generate(self, ykman_cli):  # noqa: E501
        with pytest.raises(SystemExit):
            ykman_cli('piv', 'change-management-key',
                      '-m', DEFAULT_MANAGEMENT_KEY,
                      '-n', NON_DEFAULT_MANAGEMENT_KEY,
                      '-g')
