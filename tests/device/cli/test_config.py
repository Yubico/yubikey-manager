from yubikit.core import TRANSPORT
from .. import condition

import time
import contextlib
import io
import pytest


VALID_LOCK_CODE = "a" * 32
INVALID_LOCK_CODE_NON_HEX = "z" * 32


class TestConfigUSB:
    @pytest.fixture(autouse=True)
    @condition.min_version(5)
    def enable_all(self, ykman_cli):
        ykman_cli("config", "usb", "--enable-all", "-f")
        time.sleep(1.5)
        yield None
        ykman_cli("config", "usb", "--enable-all", "-f")
        time.sleep(1.5)

    def test_disable_otp(self, ykman_cli):
        ykman_cli("config", "usb", "--disable", "OTP", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "OTP" not in output

    def test_disable_u2f(self, ykman_cli):
        ykman_cli("config", "usb", "--disable", "U2F", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO U2F" not in output

    def test_disable_openpgp(self, ykman_cli):
        ykman_cli("config", "usb", "--disable", "OPENPGP", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "OpenPGP" not in output

    def test_disable_openpgp_alternative_syntax(self, ykman_cli):
        ykman_cli("config", "usb", "--disable", "openpgp", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "OpenPGP" not in output

    def test_disable_piv(self, ykman_cli):
        ykman_cli("config", "usb", "--disable", "PIV", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "PIV" not in output

    def test_disable_oath(self, ykman_cli):
        ykman_cli("config", "usb", "--disable", "OATH", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "OATH" not in output

    def test_disable_fido2(self, ykman_cli):
        ykman_cli("config", "usb", "--disable", "FIDO2", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO2" not in output

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

    def test_mode_command(self, ykman_cli):
        ykman_cli("config", "mode", "ccid", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO U2F" not in output
        assert "FIDO2" not in output
        assert "OTP" not in output

        ykman_cli("config", "mode", "otp", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "FIDO U2F" not in output
        assert "FIDO2" not in output
        assert "OpenPGP" not in output
        assert "PIV" not in output
        assert "OATH" not in output

        ykman_cli("config", "mode", "fido", "-f")
        time.sleep(1.5)
        output = ykman_cli("config", "usb", "--list").output
        assert "OTP" not in output
        assert "OATH" not in output
        assert "PIV" not in output
        assert "OpenPGP" not in output

        # Prevent communication errors in other tests
        time.sleep(1)

    def test_mode_alias(self, ykman_cli):
        with io.StringIO() as buf:
            with contextlib.redirect_stderr(buf):
                ykman_cli("mode", "ccid", "-f")
                time.sleep(1.5)
                output = ykman_cli("config", "usb", "--list").output
                assert "FIDO U2F" not in output
                assert "FIDO2" not in output
                assert "OTP" not in output
            err = buf.getvalue()
        assert "config mode ccid" in err

        # Prevent communication errors in other tests
        time.sleep(1)


class TestConfigNFC:
    @pytest.fixture(autouse=True)
    @condition.min_version(5)
    @condition.has_transport(TRANSPORT.NFC)
    def enable_all_nfc(self, ykman_cli):
        ykman_cli("config", "nfc", "--enable-all", "-f")
        time.sleep(1.5)
        yield None
        ykman_cli("config", "nfc", "--enable-all", "-f")
        time.sleep(1.5)

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
    @condition.min_version(5)
    def preconditions(self):
        pass

    def test_set_lock_code(self, ykman_cli):
        ykman_cli("config", "set-lock-code", "--new-lock-code", VALID_LOCK_CODE)
        time.sleep(1.5)
        output = ykman_cli("info").output
        assert "Configured capabilities are protected by a lock code" in output
        ykman_cli("config", "set-lock-code", "-l", VALID_LOCK_CODE, "--clear")
        time.sleep(1.5)
        output = ykman_cli("info").output
        assert "Configured capabilities are protected by a lock code" not in output

    def test_set_invalid_lock_code(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli("config", "set-lock-code", "--new-lock-code", "aaaa")

        with pytest.raises(SystemExit):
            ykman_cli(
                "config", "set-lock-code", "--new-lock-code", INVALID_LOCK_CODE_NON_HEX
            )
