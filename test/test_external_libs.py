from test.util import ykman_cli


class TestExternalLibraries(object):

    def test_ykman_version(self):
        output = ykman_cli('-v')
        # Test that major version is 1 on all libs
        assert 'libykpers 1' in output
        assert 'libusb 1' in output

    def test_ykman_version_not_found(self):
        output = ykman_cli('-v')
        assert 'not found!' not in output
        assert '<pyusb backend missing>' not in output
