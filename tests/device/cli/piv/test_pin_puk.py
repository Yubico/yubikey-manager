from .util import (
    old_new_new,
    NON_DEFAULT_PIN,
    NON_DEFAULT_PUK,
)
from ykman.piv import OBJECT_ID_PIVMAN_DATA, PivmanData
from yubikit.management import CAPABILITY

import pytest
import re


class TestPin:
    def test_change_pin(self, ykman_cli, keys):
        ykman_cli("piv", "access", "change-pin", "-P", keys.pin, "-n", NON_DEFAULT_PIN)
        with pytest.raises(SystemExit):
            ykman_cli(
                "piv", "access", "change-pin", "-P", keys.pin, "-n", NON_DEFAULT_PIN
            )

    def test_change_pin_prompt(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "access",
            "change-pin",
            input=old_new_new(keys.pin, NON_DEFAULT_PIN),
        )
        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "access",
                "change-pin",
                input=old_new_new(keys.pin, NON_DEFAULT_PIN),
            )


class TestPuk:
    def test_change_puk(self, ykman_cli, keys):
        o1 = ykman_cli(
            "piv", "access", "change-puk", "-p", keys.puk, "-n", NON_DEFAULT_PUK
        ).output
        assert "New PUK set." in o1

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv", "access", "change-puk", "-p", keys.puk, "-n", NON_DEFAULT_PUK
            ).output

    def test_change_puk_prompt(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "access",
            "change-puk",
            input=old_new_new(keys.puk, NON_DEFAULT_PUK),
        )
        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "access",
                "change-puk",
                input=old_new_new(keys.puk, NON_DEFAULT_PUK),
            )

    def test_unblock_pin(self, ykman_cli, keys):
        for _ in range(3):
            with pytest.raises(SystemExit):
                ykman_cli(
                    "piv",
                    "access",
                    "change-pin",
                    "-P",
                    NON_DEFAULT_PIN,
                    "-n",
                    keys.pin,
                )

        o = ykman_cli("piv", "info").output
        assert re.search(r"PIN tries remaining:\s+0(/3)?", o)

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv", "access", "change-pin", "-p", keys.pin, "-n", NON_DEFAULT_PIN
            )

        o = ykman_cli(
            "piv", "access", "unblock-pin", "-p", keys.puk, "-n", NON_DEFAULT_PIN
        ).output
        assert "New PIN set" in o
        o = ykman_cli("piv", "info").output
        assert re.search(r"PIN tries remaining:\s+3(/3)?", o)


class TestSetRetries:
    def test_set_retries(self, ykman_cli, default_keys, version):
        ykman_cli(
            "piv",
            "access",
            "set-retries",
            "5",
            "6",
            input=f"{default_keys.mgmt}\n{default_keys.pin}\ny\n",
        )

        o = ykman_cli("piv", "info").output
        assert re.search(r"PIN tries remaining:\s+5(/5)?", o)
        if version >= (5, 3):
            assert re.search(r"PUK tries remaining:\s+6/6", o)

    def test_set_retries_clears_puk_blocked(self, ykman_cli, keys, info):
        if CAPABILITY.PIV in info.fips_capable:
            pytest.skip("YubiKey FIPS")

        for _ in range(3):
            with pytest.raises(SystemExit):
                ykman_cli(
                    "piv",
                    "access",
                    "change-puk",
                    "-p",
                    NON_DEFAULT_PUK,
                    "-n",
                    keys.puk,
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
            keys.mgmt,
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
            input=f"{keys.mgmt}\n{keys.pin}\ny\n",
        )

        o = ykman_cli("piv", "info").output
        assert "PUK is blocked" not in o
