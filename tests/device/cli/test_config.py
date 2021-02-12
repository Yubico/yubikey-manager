from yubikit.core import TRANSPORT
from yubikit.management import CAPABILITY
from ykman.base import YUBIKEY
from .. import condition

import contextlib
import io
import pytest


VALID_LOCK_CODE = "a" * 32
INVALID_LOCK_CODE_NON_HEX = "z" * 32


def _fido_only(capabilities):
    return capabilities & ~(CAPABILITY.U2F | CAPABILITY.FIDO2) == 0


def not_sky(device, info):
    if device.transport == TRANSPORT.NFC:
        return not (
            info.serial is None
            and _fido_only(info.supported_capabilities[TRANSPORT.USB])
        )
    else:
        return device.pid.get_type() != YUBIKEY.SKY


class TestConfigUSB:
    @pytest.fixture(autouse=True)
    @condition(not_sky)
    @condition.min_version(5)
    def enable_all(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--enable-all", "-f")
        await_reboot()
        yield None
        ykman_cli("config", "usb", "--enable-all", "-f")
        await_reboot()

    @condition.capability(CAPABILITY.OTP)
    def test_disable_otp(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--disable", "OTP", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "OTP" not in output

    @condition.capability(CAPABILITY.U2F)
    def test_disable_u2f(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--disable", "U2F", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO U2F" not in output

    @condition.capability(CAPABILITY.OPENPGP)
    def test_disable_openpgp(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--disable", "OPENPGP", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "OpenPGP" not in output

    @condition.capability(CAPABILITY.OPENPGP)
    def test_disable_openpgp_alternative_syntax(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--disable", "openpgp", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "OpenPGP" not in output

    @condition.capability(CAPABILITY.PIV)
    def test_disable_piv(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--disable", "PIV", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "PIV" not in output

    @condition.capability(CAPABILITY.OATH)
    def test_disable_oath(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--disable", "OATH", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "OATH" not in output

    @condition.capability(CAPABILITY.FIDO2)
    def test_disable_fido2(self, ykman_cli, await_reboot):
        ykman_cli("config", "usb", "--disable", "FIDO2", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO2" not in output

    @condition.capability(CAPABILITY.FIDO2)
    def test_disable_and_enable(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli("config", "usb", "--disable", "FIDO2", "--enable", "FIDO2", "-f")
        with pytest.raises(SystemExit):
            ykman_cli("config", "usb", "--enable-all", "--disable", "FIDO2", "-f")

    def test_disable_all(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli(
                "config",
                "usb",
                "-d",
                "FIDO2",
                "-d",
                "U2F",
                "-d",
                "OATH",
                "-d",
                "OPENPGP",
                "PIV",
                "-d",
                "OTP",
            )

    def test_mode_command(self, ykman_cli, await_reboot):
        ykman_cli("config", "mode", "ccid", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO U2F" not in output
        assert "FIDO2" not in output
        assert "OTP" not in output

        ykman_cli("config", "mode", "otp", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO U2F" not in output
        assert "FIDO2" not in output
        assert "OpenPGP" not in output
        assert "PIV" not in output
        assert "OATH" not in output

        ykman_cli("config", "mode", "fido", "-f")
        await_reboot()
        output = ykman_cli("config", "usb", "--list").output
        assert "OTP" not in output
        assert "OATH" not in output
        assert "PIV" not in output
        assert "OpenPGP" not in output

    def test_mode_alias(self, ykman_cli, await_reboot):
        with io.StringIO() as buf:
            with contextlib.redirect_stderr(buf):
                ykman_cli("mode", "ccid", "-f")
                await_reboot()
                output = ykman_cli("config", "usb", "--list").output
                assert "FIDO U2F" not in output
                assert "FIDO2" not in output
                assert "OTP" not in output
            err = buf.getvalue()
        assert "config mode ccid" in err


class TestConfigNFC:
    @pytest.fixture(autouse=True)
    @condition(not_sky)
    @condition.min_version(5)
    @condition.has_transport(TRANSPORT.NFC)
    def enable_all_nfc(self, ykman_cli, await_reboot):
        ykman_cli("config", "nfc", "--enable-all", "-f")
        await_reboot()
        yield None
        ykman_cli("config", "nfc", "--enable-all", "-f")
        await_reboot()

    def test_disable_otp(self, ykman_cli):
        ykman_cli("config", "nfc", "--disable", "OTP", "-f")
        output = ykman_cli("config", "nfc", "--list").output
        assert "OTP" not in output

    def test_disable_u2f(self, ykman_cli):
        ykman_cli("config", "nfc", "--disable", "U2F", "-f")
        output = ykman_cli("config", "nfc", "--list").output
        assert "FIDO U2F" not in output

    def test_disable_openpgp(self, ykman_cli):
        ykman_cli("config", "nfc", "--disable", "OPENPGP", "-f")
        output = ykman_cli("config", "nfc", "--list").output
        assert "OpenPGP" not in output

    def test_disable_piv(self, ykman_cli):
        ykman_cli("config", "nfc", "--disable", "PIV", "-f")
        output = ykman_cli("config", "nfc", "--list").output
        assert "PIV" not in output

    def test_disable_oath(self, ykman_cli):
        ykman_cli("config", "nfc", "--disable", "OATH", "-f")
        output = ykman_cli("config", "nfc", "--list").output
        assert "OATH" not in output

    def test_disable_fido2(self, ykman_cli):
        ykman_cli("config", "nfc", "--disable", "FIDO2", "-f")
        output = ykman_cli("config", "nfc", "--list").output
        assert "FIDO2" not in output

    @condition.transport(TRANSPORT.USB)
    def test_disable_all(self, ykman_cli):
        ykman_cli("config", "nfc", "--disable-all", "-f")
        output = ykman_cli("config", "nfc", "--list").output
        assert not output

    def test_disable_and_enable(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli("config", "nfc", "--disable", "FIDO2", "--enable", "FIDO2", "-f")
        with pytest.raises(SystemExit):
            ykman_cli("config", "nfc", "--disable-all", "--enable", "FIDO2", "-f")
        with pytest.raises(SystemExit):
            ykman_cli("config", "nfc", "--enable-all", "--disable", "FIDO2", "-f")
        with pytest.raises(SystemExit):
            ykman_cli("config", "nfc", "--enable-all", "--disable-all", "FIDO2", "-f")


class TestConfigLockCode:
    @pytest.fixture(autouse=True)
    @condition.min_version(5)
    def preconditions(self):
        pass

    def test_set_lock_code(self, ykman_cli):
        ykman_cli("config", "set-lock-code", "--new-lock-code", VALID_LOCK_CODE)
        output = ykman_cli("info").output
        assert "Configured capabilities are protected by a lock code" in output
        ykman_cli("config", "set-lock-code", "-l", VALID_LOCK_CODE, "--clear")
        output = ykman_cli("info").output
        assert "Configured capabilities are protected by a lock code" not in output

    def test_set_invalid_lock_code(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli("config", "set-lock-code", "--new-lock-code", "aaaa")

        with pytest.raises(SystemExit):
            ykman_cli(
                "config", "set-lock-code", "--new-lock-code", INVALID_LOCK_CODE_NON_HEX
            )
