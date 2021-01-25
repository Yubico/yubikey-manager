from yubikit.piv import OBJECT_ID
import pytest


DEFAULT_MANAGEMENT_KEY = "010203040506070801020304050607080102030405060708"


class TestMisc:
    def setUp(self, ykman_cli):
        ykman_cli("piv", "reset", "-f")

    def test_info(self, ykman_cli):
        output = ykman_cli("piv", "info").output
        assert "PIV version:" in output

    def test_reset(self, ykman_cli):
        output = ykman_cli("piv", "reset", "-f").output
        assert "Success!" in output

    def test_export_invalid_certificate_fails(self, ykman_cli):
        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID.AUTHENTICATION),
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            input="This is not a cert",
        )

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv", "certificates", "export", hex(OBJECT_ID.AUTHENTICATION), "-"
            )

    def test_info_with_invalid_certificate_does_not_crash(self, ykman_cli):
        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID.AUTHENTICATION),
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            input="This is not a cert",
        )
        ykman_cli("piv", "info")
