from yubikit.management import CAPABILITY
from yubikit.core import NotSupportedError
from ....util import open_file
from ... import condition
import pytest


@pytest.fixture(autouse=True)
@condition.fips(True)
@condition.capability(CAPABILITY.PIV)
def ensure_piv(ykman_cli):
    ykman_cli("piv", "reset", "-f")


class TestFIPS:
    def test_rsa1024_generate_blocked(self, ykman_cli):
        with pytest.raises(NotSupportedError):
            ykman_cli("piv", "keys", "generate", "9a", "-a", "RSA1024", "-")

    def test_rsa1024_import_blocked(self, ykman_cli):
        with pytest.raises(NotSupportedError):
            with open_file("rsa_1024_key.pem") as f:
                ykman_cli("piv", "keys", "import", "9a", f.name)
