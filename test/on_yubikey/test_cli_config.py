import pytest
from .framework import yubikey_conditions


VALID_LOCK_CODE = 'a' * 32
INVALID_LOCK_CODE_NON_HEX = 'z' * 32


@yubikey_conditions.can_write_config
class TestConfigUSB(object):

    @pytest.fixture(autouse=True)
    def setUpTearDown(self, ykman_cli):
        ykman_cli('config', 'usb', '--enable-all', '-f')
        yield None
        ykman_cli('config', 'usb', '--enable-all', '-f')

    def test_disable_otp(self, ykman_cli):
        ykman_cli('config', 'usb', '--disable', 'OTP', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'OTP' not in output

    def test_disable_u2f(self, ykman_cli):
        ykman_cli('config', 'usb', '--disable', 'U2F', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'FIDO U2F' not in output

    def test_disable_openpgp(self, ykman_cli):
        ykman_cli('config', 'usb', '--disable', 'OPGP', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'OpenPGP' not in output

    def test_disable_openpgp_alternative_syntax(self, ykman_cli):
        ykman_cli('config', 'usb', '--disable', 'openpgp', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'OpenPGP' not in output

    def test_disable_piv(self, ykman_cli):
        ykman_cli('config', 'usb', '--disable', 'PIV', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'PIV' not in output

    def test_disable_oath(self, ykman_cli):
        ykman_cli('config', 'usb', '--disable', 'OATH', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'OATH' not in output

    def test_disable_fido2(self, ykman_cli):
        ykman_cli('config', 'usb', '--disable', 'FIDO2', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'FIDO2' not in output

    def test_disable_and_enable(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'usb', '--disable', 'FIDO2', '--enable',
                'FIDO2', '-f')
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'usb', '--enable-all', '--disable', 'FIDO2', '-f')

    def test_disable_all(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'usb', '-d', 'FIDO2', '-d', 'U2F', '-d',
                'OATH', '-d', 'OPGP', 'PIV', '-d', 'OTP')

    def test_mode_command(self, ykman_cli):
        ykman_cli('mode', 'ccid', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'FIDO U2F' not in output
        assert 'FIDO2' not in output
        assert 'OTP' not in output

        ykman_cli('mode', 'otp', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'FIDO U2F' not in output
        assert 'FIDO2' not in output
        assert 'OpenPGP' not in output
        assert 'PIV' not in output
        assert 'OATH' not in output

        ykman_cli('mode', 'fido', '-f')
        output = ykman_cli('config', 'usb', '--list')
        assert 'OTP' not in output
        assert 'OATH' not in output
        assert 'PIV' not in output
        assert 'OpenPGP' not in output


@yubikey_conditions.can_write_config
class TestConfigNFC(object):

    @pytest.fixture(autouse=True)
    def setUpTearDown(self, ykman_cli):
        ykman_cli('config', 'nfc', '--enable-all', '-f')
        yield None
        ykman_cli('config', 'nfc', '--enable-all', '-f')

    def test_disable_otp(self, ykman_cli):
        ykman_cli('config', 'nfc', '--disable', 'OTP', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        assert 'OTP' not in output

    def test_disable_u2f(self, ykman_cli):
        ykman_cli('config', 'nfc', '--disable', 'U2F', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        assert 'FIDO U2F' not in output

    def test_disable_openpgp(self, ykman_cli):
        ykman_cli('config', 'nfc', '--disable', 'OPGP', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        assert 'OpenPGP' not in output

    def test_disable_piv(self, ykman_cli):
        ykman_cli('config', 'nfc', '--disable', 'PIV', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        assert 'PIV' not in output

    def test_disable_oath(self, ykman_cli):
        ykman_cli('config', 'nfc', '--disable', 'OATH', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        assert 'OATH' not in output

    def test_disable_fido2(self, ykman_cli):
        ykman_cli('config', 'nfc', '--disable', 'FIDO2', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        assert 'FIDO2' not in output

    def test_disable_all(self, ykman_cli):
        ykman_cli('config', 'nfc', '--disable-all', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        assert not output

    def test_disable_and_enable(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'nfc', '--disable', 'FIDO2',
                '--enable', 'FIDO2', '-f')
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'nfc', '--disable-all', '--enable', 'FIDO2', '-f')
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'nfc', '--enable-all', '--disable', 'FIDO2', '-f')
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'nfc', '--enable-all', '--disable-all',
                'FIDO2', '-f')


@yubikey_conditions.can_write_config
class TestConfigLockCode(object):

    @pytest.fixture(autouse=True)
    def setUpTearDown(self, ykman_cli):
        try:
            ykman_cli(
                'config', 'set-lock-code', '-l', VALID_LOCK_CODE, '--clear')
        except SystemExit:
            pass

        yield None

        try:
            ykman_cli(
                'config', 'set-lock-code', '-l', VALID_LOCK_CODE, '--clear')
        except SystemExit:
            pass

    def test_set_lock_code(self, ykman_cli):
        ykman_cli(
            'config', 'set-lock-code', '--new-lock-code', VALID_LOCK_CODE)
        output1 = ykman_cli('info')

        ykman_cli(
            'config', 'set-lock-code', '-l', VALID_LOCK_CODE, '--clear')
        output2 = ykman_cli('info')

        assert 'Configured applications are protected by a lock code' in output1
        assert(
            'Configured applications are protected by a lock code'
            not in output2)

    def test_set_invalid_lock_code(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'set-lock-code',
                '--new-lock-code', 'aaaa')

        with pytest.raises(SystemExit):
            ykman_cli(
                'config', 'set-lock-code',
                '--new-lock-code', INVALID_LOCK_CODE_NON_HEX)
