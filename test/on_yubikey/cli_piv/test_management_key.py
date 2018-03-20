import re
from ..util import ykman_cli
from .util import (
    PivTestCase, old_new_new, DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY,
    NON_DEFAULT_MANAGEMENT_KEY)


class ManagementKey(PivTestCase):

    @classmethod
    def setUp(cls):
        ykman_cli('piv', 'reset', '-f')

    def test_change_management_key_protect_random(self):
        ykman_cli(
            'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
            '-m', DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        self.assertIn(
            'Management key is stored on the YubiKey, protected by PIN',
            output)

        with self.assertRaises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                '-m', DEFAULT_MANAGEMENT_KEY)

        # Should succeed - PIN as key
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN)

    def test_change_management_key_protect_prompt(self):
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                  input=DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        self.assertIn(
            'Management key is stored on the YubiKey, protected by PIN',
            output)

        with self.assertRaises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                'piv', 'change-management-key', '-p', '-P', DEFAULT_PIN,
                '-m', DEFAULT_MANAGEMENT_KEY)

        # Should succeed - PIN as key
        ykman_cli('piv', 'change-management-key', '-p', '-P', DEFAULT_PIN)

    def test_change_management_key_no_protect_random(self):
        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', DEFAULT_MANAGEMENT_KEY)
        self.assertRegex(
            output, re.compile(
                r'^Generated management key: [a-f0-9]{48}$', re.MULTILINE))

        output = ykman_cli('piv', 'info')
        self.assertNotIn('Management key is stored on the YubiKey', output)

    def test_change_management_key_no_protect_arg(self):
        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', DEFAULT_MANAGEMENT_KEY,
            '-n', NON_DEFAULT_MANAGEMENT_KEY)
        self.assertEqual('', output)
        output = ykman_cli('piv', 'info')
        self.assertNotIn('Management key is stored on the YubiKey', output)

        with self.assertRaises(SystemExit):
            ykman_cli(
                'piv', 'change-management-key',
                '-m', DEFAULT_MANAGEMENT_KEY,
                '-n', NON_DEFAULT_MANAGEMENT_KEY)

        output = ykman_cli(
            'piv', 'change-management-key',
            '-m', NON_DEFAULT_MANAGEMENT_KEY,
            '-n', DEFAULT_MANAGEMENT_KEY)
        self.assertEqual('', output)

    def test_change_management_key_no_protect_prompt(self):
        output = ykman_cli('piv', 'change-management-key',
                           input=old_new_new(DEFAULT_MANAGEMENT_KEY,
                                             NON_DEFAULT_MANAGEMENT_KEY))
        self.assertNotIn('Generated', output)
        output = ykman_cli('piv', 'info')
        self.assertNotIn('Management key is stored on the YubiKey', output)

        with self.assertRaises(SystemExit):
            ykman_cli('piv', 'change-management-key',
                      input=old_new_new(DEFAULT_MANAGEMENT_KEY,
                                        NON_DEFAULT_MANAGEMENT_KEY))

        ykman_cli('piv', 'change-management-key',
                  input=old_new_new(NON_DEFAULT_MANAGEMENT_KEY,
                                    DEFAULT_MANAGEMENT_KEY))
        self.assertNotIn('Generated', output)
