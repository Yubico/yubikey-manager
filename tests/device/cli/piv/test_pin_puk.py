from .util import (
    old_new_new,
    DEFAULT_PIN,
    NON_DEFAULT_PIN,
    DEFAULT_PUK,
    NON_DEFAULT_PUK,
    DEFAULT_MANAGEMENT_KEY,
)
from ykman.piv import OBJECT_ID_PIVMAN_DATA, PivmanData

import pytest
import re


class TestPin:
    def test_change_pin(self, ykman_cli):
        ykman_cli(
            "piv", "access", "change-pin", "-P", DEFAULT_PIN, "-n", NON_DEFAULT_PIN
        )
        ykman_cli(
            "piv", "access", "change-pin", "-P", NON_DEFAULT_PIN, "-n", DEFAULT_PIN
        )

    def test_change_pin_prompt(self, ykman_cli):
        ykman_cli(
            "piv",
            "access",
            "change-pin",
            input=old_new_new(DEFAULT_PIN, NON_DEFAULT_PIN),
        )
        ykman_cli(
            "piv",
            "access",
            "change-pin",
            input=old_new_new(NON_DEFAULT_PIN, DEFAULT_PIN),
        )


class TestPuk:
    def test_change_puk(self, ykman_cli):
        o1 = ykman_cli(
            "piv", "access", "change-puk", "-p", DEFAULT_PUK, "-n", NON_DEFAULT_PUK
        ).output
        assert "New PUK set." in o1

        o2 = ykman_cli(
            "piv", "access", "change-puk", "-p", NON_DEFAULT_PUK, "-n", DEFAULT_PUK
        ).output
        assert "New PUK set." in o2

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv", "access", "change-puk", "-p", NON_DEFAULT_PUK, "-n", DEFAULT_PUK
            )

    def test_change_puk_prompt(self, ykman_cli):
        ykman_cli(
            "piv",
            "access",
            "change-puk",
            input=old_new_new(DEFAULT_PUK, NON_DEFAULT_PUK),
        )
        ykman_cli(
            "piv",
            "access",
            "change-puk",
            input=old_new_new(NON_DEFAULT_PUK, DEFAULT_PUK),
        )

    def test_unblock_pin(self, ykman_cli):
        for _ in range(3):
            with pytest.raises(SystemExit):
                ykman_cli(
                    "piv",
                    "access",
                    "change-pin",
                    "-P",
                    NON_DEFAULT_PIN,
                    "-n",
                    DEFAULT_PIN,
                )

        o = ykman_cli("piv", "info").output
        assert re.search(r"PIN tries remaining:\s+0(/3)?", o)

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv", "access", "change-pin", "-p", DEFAULT_PIN, "-n", NON_DEFAULT_PIN
            )

        o = ykman_cli(
            "piv", "access", "unblock-pin", "-p", DEFAULT_PUK, "-n", DEFAULT_PIN
        ).output
        assert "PIN unblocked" in o
        o = ykman_cli("piv", "info").output
        assert re.search(r"PIN tries remaining:\s+3(/3)?", o)


class TestSetRetries:
    def test_set_retries(self, ykman_cli, version):
        ykman_cli(
            "piv",
            "access",
            "set-retries",
            "5",
            "6",
            input=f"{DEFAULT_MANAGEMENT_KEY}\n{DEFAULT_PIN}\ny\n",
        )

        o = ykman_cli("piv", "info").output
        assert re.search(r"PIN tries remaining:\s+5(/5)?", o)
        if version >= (5, 3):
            assert re.search(r"PUK tries remaining:\s+6/6", o)

    def test_set_retries_clears_puk_blocked(self, ykman_cli):
        for _ in range(3):
            with pytest.raises(SystemExit):
                ykman_cli(
                    "piv",
                    "access",
                    "change-puk",
                    "-p",
                    NON_DEFAULT_PUK,
                    "-n",
                    DEFAULT_PUK,
                )

        pivman = PivmanData()
        pivman.puk_blocked = True

        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID_PIVMAN_DATA),
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            input=pivman.get_bytes(),
        )

        o = ykman_cli("piv", "info").output
        assert "PUK is blocked" in o

        ykman_cli(
            "piv",
            "access",
            "set-retries",
            "3",
            "3",
            input=f"{DEFAULT_MANAGEMENT_KEY}\n{DEFAULT_PIN}\ny\n",
        )

        o = ykman_cli("piv", "info").output
        assert "PUK is blocked" not in o
