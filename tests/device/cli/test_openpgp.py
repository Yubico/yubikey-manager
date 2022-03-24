from yubikit.management import CAPABILITY
from .. import condition
import pytest

DEFAULT_PIN = "123456"
NON_DEFAULT_PIN = "654321"
DEFAULT_ADMIN_PIN = "12345678"
NON_DEFAULT_ADMIN_PIN = "87654321"


def old_new_new(old, new):
    return f"{old}\n{new}\n{new}\n"


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.OPENPGP)
def preconditions(ykman_cli):
    ykman_cli("openpgp", "reset", "-f")


class TestOpenPGP:
    def test_openpgp_info(self, ykman_cli):
        output = ykman_cli("openpgp", "info").output
        assert "OpenPGP version:" in output

    def test_openpgp_reset(self, ykman_cli):
        output = ykman_cli("openpgp", "reset", "-f").output
        assert "Success! All data has been cleared and default PINs are set." in output


class TestPin:
    def test_change_pin(self, ykman_cli):
        ykman_cli(
            "openpgp", "access", "change-pin", "-P", DEFAULT_PIN, "-n", NON_DEFAULT_PIN
        )
        ykman_cli(
            "openpgp", "access", "change-pin", "-P", NON_DEFAULT_PIN, "-n", DEFAULT_PIN
        )

    def test_change_pin_prompt(self, ykman_cli):
        ykman_cli(
            "openpgp",
            "access",
            "change-pin",
            input=old_new_new(DEFAULT_PIN, NON_DEFAULT_PIN),
        )
        ykman_cli(
            "openpgp",
            "access",
            "change-pin",
            input=old_new_new(NON_DEFAULT_PIN, DEFAULT_PIN),
        )


class TestAdminPin:
    def test_change_admin_pin(self, ykman_cli):
        ykman_cli(
            "openpgp",
            "access",
            "change-admin-pin",
            "-a",
            DEFAULT_ADMIN_PIN,
            "-n",
            NON_DEFAULT_ADMIN_PIN,
        )
        ykman_cli(
            "openpgp",
            "access",
            "change-admin-pin",
            "-a",
            NON_DEFAULT_ADMIN_PIN,
            "-n",
            DEFAULT_ADMIN_PIN,
        )

    def test_change_pin_prompt(self, ykman_cli):
        ykman_cli(
            "openpgp",
            "access",
            "change-admin-pin",
            input=old_new_new(DEFAULT_ADMIN_PIN, NON_DEFAULT_ADMIN_PIN),
        )
        ykman_cli(
            "openpgp",
            "access",
            "change-admin-pin",
            input=old_new_new(NON_DEFAULT_ADMIN_PIN, DEFAULT_ADMIN_PIN),
        )


class TestForceSignature:
    def test_set_force_sig(self, ykman_cli):
        ykman_cli(
            "openpgp",
            "access",
            "set-signature-policy",
            "ALWAYS",
            "-a",
            DEFAULT_ADMIN_PIN,
        )

        output = ykman_cli("openpgp", "info").output
        assert "Always" in output

        ykman_cli(
            "openpgp", "access", "set-signature-policy", "ONCE", "-a", DEFAULT_ADMIN_PIN
        )

        output = ykman_cli("openpgp", "info").output
        assert "Once" in output

    def test_set_force_sig_prompt(self, ykman_cli):
        ykman_cli(
            "openpgp",
            "access",
            "set-signature-policy",
            "ALWAYS",
            input=DEFAULT_ADMIN_PIN,
        )

        output = ykman_cli("openpgp", "info").output
        assert "Always" in output

        ykman_cli(
            "openpgp",
            "access",
            "set-signature-policy",
            "ONCE",
            input=DEFAULT_ADMIN_PIN,
        )

        output = ykman_cli("openpgp", "info").output
        assert "Once" in output
