from .util import old_new_new, NON_DEFAULT_MANAGEMENT_KEY
import re
import pytest


class TestManagementKey:
    def test_change_management_key_force_fails_without_generate(self, ykman_cli, keys):
        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "access",
                "change-management-key",
                "-P",
                keys.pin,
                "-m",
                keys.mgmt,
                "-f",
            )

    def test_change_management_key_protect_random(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "access",
            "change-management-key",
            "-p",
            "-P",
            keys.pin,
            "-m",
            keys.mgmt,
        )
        output = ykman_cli("piv", "info").output
        assert "Management key is stored on the YubiKey, protected by PIN" in output

        with pytest.raises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                "piv",
                "access",
                "change-management-key",
                "-p",
                "-P",
                keys.pin,
                "-m",
                keys.mgmt,
            )

        # Should succeed - PIN as key
        ykman_cli("piv", "access", "change-management-key", "-p", "-P", keys.pin)

    def test_change_management_key_protect_prompt(self, ykman_cli, keys):
        ykman_cli(
            "piv",
            "access",
            "change-management-key",
            "-p",
            "-P",
            keys.pin,
            input=keys.mgmt,
        )
        output = ykman_cli("piv", "info").output
        assert "Management key is stored on the YubiKey, protected by PIN" in output

        with pytest.raises(SystemExit):
            # Should fail - wrong current key
            ykman_cli(
                "piv",
                "access",
                "change-management-key",
                "-p",
                "-P",
                keys.pin,
                "-m",
                keys.mgmt,
            )

        # Should succeed - PIN as key
        ykman_cli("piv", "access", "change-management-key", "-p", "-P", keys.pin)

    def test_change_management_key_no_protect_generate(self, ykman_cli, keys):
        output = ykman_cli(
            "piv", "access", "change-management-key", "-m", keys.mgmt, "-g"
        ).output

        assert re.match(
            r"^Generated management key: [a-f0-9]{48}$", output, re.MULTILINE
        )

        output = ykman_cli("piv", "info").output
        assert "Management key is stored on the YubiKey" not in output

    def test_change_management_key_no_protect_arg(self, ykman_cli, keys):
        output = ykman_cli(
            "piv",
            "access",
            "change-management-key",
            "-m",
            keys.mgmt,
            "-n",
            NON_DEFAULT_MANAGEMENT_KEY,
        ).output
        assert "New management key set" in output
        output = ykman_cli("piv", "info").output
        assert "Management key is stored on the YubiKey" not in output

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "access",
                "change-management-key",
                "-m",
                keys.mgmt,
                "-n",
                NON_DEFAULT_MANAGEMENT_KEY,
            )

        output = ykman_cli(
            "piv",
            "access",
            "change-management-key",
            "-m",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-n",
            keys.mgmt,
        ).output
        assert "New management key set" in output

    def test_change_management_key_no_protect_arg_bad_length(self, ykman_cli, keys):
        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "access",
                "change-management-key",
                "-m",
                keys.mgmt,
                "-n",
                "10020304050607080102030405060708",
            )

    def test_change_management_key_no_protect_prompt(self, ykman_cli, keys):
        output = ykman_cli(
            "piv",
            "access",
            "change-management-key",
            input=old_new_new(keys.mgmt, NON_DEFAULT_MANAGEMENT_KEY),
        ).output
        assert "Generated" not in output
        output = ykman_cli("piv", "info").output
        assert "Management key is stored on the YubiKey" not in output

        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "access",
                "change-management-key",
                input=old_new_new(keys.mgmt, NON_DEFAULT_MANAGEMENT_KEY),
            )

        ykman_cli(
            "piv",
            "access",
            "change-management-key",
            input=old_new_new(NON_DEFAULT_MANAGEMENT_KEY, keys.mgmt),
        )
        assert "Generated" not in output

    def test_change_management_key_new_key_conflicts_with_generate(
        self, ykman_cli, keys
    ):
        with pytest.raises(SystemExit):
            ykman_cli(
                "piv",
                "access",
                "change-management-key",
                "-m",
                keys.mgmt,
                "-n",
                NON_DEFAULT_MANAGEMENT_KEY,
                "-g",
            )
