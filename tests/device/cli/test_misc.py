from .. import condition
import pytest


class TestYkmanInfo:
    def test_ykman_info(self, ykman_cli, info):
        output = ykman_cli("info").output
        assert "Device type:" in output
        if info.serial is not None:
            assert "Serial number:" in output
        assert "Firmware version:" in output

    @condition.fips(False)
    def test_ykman_info_does_not_report_fips_for_non_fips_device(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli("info", "--check-fips")

    @condition.fips(True)
    def test_ykman_info_reports_fips_status(self, ykman_cli):
        info = ykman_cli("info", "--check-fips").output
        assert "FIPS Approved Mode:" in info
        assert "  FIDO U2F:" in info
        assert "  OATH:" in info
        assert "  OTP:" in info
