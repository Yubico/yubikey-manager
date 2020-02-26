from .framework import yubikey_conditions


def test_ykman_info(ykman_cli):
    info = ykman_cli('info')
    assert 'Device type:' in info
    assert 'Serial number:' in info
    assert 'Firmware version:' in info


@yubikey_conditions.is_not_fips
def test_ykman_info_does_not_report_fips_for_non_fips_device(ykman_cli):
    info = ykman_cli('info', '--check-fips')
    assert 'FIPS' not in info


@yubikey_conditions.is_fips
def test_ykman_info_reports_fips_status(ykman_cli):
    info = ykman_cli('info', '--check-fips')
    assert 'FIPS Approved Mode:' in info
    assert '  FIDO U2F:' in info
    assert '  OATH:' in info
    assert '  OTP:' in info
