import pytest

from .util import (
    old_new_new, DEFAULT_PIN, NON_DEFAULT_PIN, DEFAULT_PUK, NON_DEFAULT_PUK)


class Pin(object):

    def test_change_pin(self, ykman_cli):
        ykman_cli('piv', 'change-pin', '-P', DEFAULT_PIN,
                  '-n', NON_DEFAULT_PIN)
        ykman_cli('piv', 'change-pin', '-P', NON_DEFAULT_PIN,
                  '-n', DEFAULT_PIN)

    def test_change_pin_prompt(self, ykman_cli):
        ykman_cli('piv', 'change-pin',
                  input=old_new_new(DEFAULT_PIN, NON_DEFAULT_PIN))
        ykman_cli('piv', 'change-pin',
                  input=old_new_new(NON_DEFAULT_PIN, DEFAULT_PIN))


class Puk(object):

    def test_change_puk(self, ykman_cli):
        o1 = ykman_cli('piv', 'change-puk', '-p', DEFAULT_PUK,
                       '-n', NON_DEFAULT_PUK)
        assert 'New PUK set.' in o1

        o2 = ykman_cli('piv', 'change-puk', '-p', NON_DEFAULT_PUK,
                       '-n', DEFAULT_PUK)
        assert 'New PUK set.' in o2

        with pytest.raises(SystemExit):
            ykman_cli('piv', 'change-puk', '-p', NON_DEFAULT_PUK,
                      '-n', DEFAULT_PUK)

    def test_change_puk_prompt(self, ykman_cli):
        ykman_cli('piv', 'change-puk',
                  input=old_new_new(DEFAULT_PUK, NON_DEFAULT_PUK))
        ykman_cli('piv', 'change-puk',
                  input=old_new_new(NON_DEFAULT_PUK, DEFAULT_PUK))
