import pytest

from yubikit.core import NotSupportedError

from ....util import open_file
from ... import condition


class TestFIPS:
    @condition.yk4_fips(True)
    def test_rsa1024_generate_blocked(self, ykman_cli):
        with pytest.raises(NotSupportedError):
            ykman_cli("piv", "keys", "generate", "9a", "-a", "RSA1024", "-")

    @condition.yk4_fips(True)
    def test_rsa1024_import_blocked(self, ykman_cli):
        with pytest.raises(NotSupportedError):
            with open_file("rsa_1024_key.pem") as f:
                ykman_cli("piv", "keys", "import", "9a", f.name)
