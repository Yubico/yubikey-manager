import pytest

from ykman.piv import OBJ
from .util import DEFAULT_MANAGEMENT_KEY


class Misc(object):

    @pytest.fixture(autouse=True, scope='class')
    def setUp(self, ykman_cli):
        ykman_cli('piv', 'reset', '-f')

    def test_info(self, ykman_cli):
        output = ykman_cli('piv', 'info')
        assert 'PIV version:' in output

    def test_reset(self, ykman_cli):
        output = ykman_cli('piv', 'reset', '-f')
        assert 'Success!' in output

    def test_export_invalid_certificate_fails(self, ykman_cli):
        ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                  '-m', DEFAULT_MANAGEMENT_KEY,
                  input='This is not a cert')

        with pytest.raises(SystemExit):
            ykman_cli('piv', 'export-certificate',
                      hex(OBJ.AUTHENTICATION), '-')

    def test_info_with_invalid_certificate_does_not_crash(self, ykman_cli):
        ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                  '-m', DEFAULT_MANAGEMENT_KEY,
                  input='This is not a cert')
        ykman_cli('piv', 'info')
