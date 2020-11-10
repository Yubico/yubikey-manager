import unittest

from yubikit.piv import OBJECT_ID
from ..framework import cli_test_suite

DEFAULT_MANAGEMENT_KEY = "010203040506070801020304050607080102030405060708"


@cli_test_suite
def additional_tests(ykman_cli):
    class Misc(unittest.TestCase):
        def setUp(self):
            ykman_cli("piv", "reset", "-f")

        def test_info(self):
            output = ykman_cli("piv", "info")
            self.assertIn("PIV version:", output)

        def test_reset(self):
            output = ykman_cli("piv", "reset", "-f")
            self.assertIn("Success!", output)

        def test_export_invalid_certificate_fails(self):
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

            with self.assertRaises(SystemExit):
                ykman_cli(
                    "piv", "certificates", "export", hex(OBJECT_ID.AUTHENTICATION), "-"
                )

        def test_info_with_invalid_certificate_does_not_crash(self):
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

    return [Misc]
