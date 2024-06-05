from yubikit.piv import OBJECT_ID
import pytest


class TestMisc:
    def setUp(self, ykman_cli):
        ykman_cli("piv", "reset", "-f")

    def test_info(self, ykman_cli):
        output = ykman_cli("piv", "info").output
        assert "PIV version:" in output

    def test_reset(self, ykman_cli):
        output = ykman_cli("piv", "reset", "-f").output
        assert "Reset complete" in output

    def test_export_invalid_certificate_fails(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID.AUTHENTICATION),
            "-",
            "-m",
            keys.mgmt,
            input="This is not a cert",
        )

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv", "certificates", "export", hex(OBJECT_ID.AUTHENTICATION), "-"
            )

    def test_info_with_invalid_certificate_does_not_crash(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID.AUTHENTICATION),
            "-",
            "-m",
            keys.mgmt,
            input="This is not a cert",
        )
        ykman_cli("piv", "info")
