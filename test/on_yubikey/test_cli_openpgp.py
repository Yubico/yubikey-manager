import pytest


class TestOpenPGP(object):

    @pytest.fixture(autouse=True)
    def setUp(self, ykman_cli):
        ykman_cli('openpgp', 'reset', '-f')

    def test_openpgp_info(self, ykman_cli):
        output = ykman_cli('openpgp', 'info')
        assert 'OpenPGP version:' in output

    def test_openpgp_reset(self, ykman_cli):
        output = ykman_cli('openpgp', 'reset', '-f')
        assert(
            'Success! All data has been cleared and default PINs are set.'
            in output)
