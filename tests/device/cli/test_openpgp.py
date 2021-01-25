from yubikit.management import CAPABILITY
from .. import condition
import pytest


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.OATH)
def preconditions(ykman_cli):
    ykman_cli("openpgp", "reset", "-f")


class TestOpenPGP:
    def test_openpgp_info(self, ykman_cli):
        output = ykman_cli("openpgp", "info").output
        assert "OpenPGP version:" in output

    def test_openpgp_reset(self, ykman_cli):
        output = ykman_cli("openpgp", "reset", "-f").output
        assert "Success! All data has been cleared and default PINs are set." in output
