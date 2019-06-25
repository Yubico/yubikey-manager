import unittest

from ..framework import cli_test_suite
from .util import (
    old_new_new, DEFAULT_PIN, NON_DEFAULT_PIN, DEFAULT_PUK, NON_DEFAULT_PUK)


@cli_test_suite
def additional_tests(ykman_cli):

    class Pin(unittest.TestCase):

        def test_change_pin(self):
            ykman_cli('piv', 'change-pin', '-P', DEFAULT_PIN,
                      '-n', NON_DEFAULT_PIN)
            ykman_cli('piv', 'change-pin', '-P', NON_DEFAULT_PIN,
                      '-n', DEFAULT_PIN)

        def test_change_pin_prompt(self):
            ykman_cli('piv', 'change-pin',
                      input=old_new_new(DEFAULT_PIN, NON_DEFAULT_PIN))
            ykman_cli('piv', 'change-pin',
                      input=old_new_new(NON_DEFAULT_PIN, DEFAULT_PIN))

    class Puk(unittest.TestCase):

        def test_change_puk(self):
            o1 = ykman_cli('piv', 'change-puk', '-p', DEFAULT_PUK,
                           '-n', NON_DEFAULT_PUK)
            self.assertIn('New PUK set.', o1)

            o2 = ykman_cli('piv', 'change-puk', '-p', NON_DEFAULT_PUK,
                           '-n', DEFAULT_PUK)
            self.assertIn('New PUK set.', o2)

            with self.assertRaises(SystemExit):
                ykman_cli('piv', 'change-puk', '-p', NON_DEFAULT_PUK,
                          '-n', DEFAULT_PUK)

        def test_change_puk_prompt(self):
            ykman_cli('piv', 'change-puk',
                      input=old_new_new(DEFAULT_PUK, NON_DEFAULT_PUK))
            ykman_cli('piv', 'change-puk',
                      input=old_new_new(NON_DEFAULT_PUK, DEFAULT_PUK))

    return [Pin, Puk]
