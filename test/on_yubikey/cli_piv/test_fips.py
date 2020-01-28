import pytest

from ...util import open_file
from ..framework import yubikey_conditions


class TestFIPS(object):

    @pytest.fixture(autouse=True)
    def setUpTearDown(self, ykman_cli):
        ykman_cli('piv', 'reset', '-f')
        yield None
        ykman_cli('piv', 'reset', '-f')

    @yubikey_conditions.is_fips
    def test_rsa1024_generate_blocked(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli('piv', 'generate-key', '9a', '-a', 'RSA1024', '-')

    @yubikey_conditions.is_fips
    def test_rsa1024_import_blocked(self, ykman_cli):
        with pytest.raises(SystemExit):
            with open_file('rsa_1024_key.pem') as f:
                ykman_cli('piv', 'import-key', '9a', f.name)
