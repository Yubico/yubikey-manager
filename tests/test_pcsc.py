from unittest.mock import MagicMock, patch

import pytest
from ykman.pcsc import kill_scdaemon, kill_yubikey_agent


@pytest.mark.parametrize("platform", ["linux", "darwin", "freebsd"])
def test_kill_yubikey_agent_success(platform):
    with (
        patch("ykman.pcsc.sys.platform", platform),
        patch("ykman.pcsc.shutil.which", return_value="/usr/bin/pkill"),
        patch("ykman.pcsc.os.path.exists", return_value=True),
        patch("ykman.pcsc.subprocess.call", return_value=0) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        result = kill_yubikey_agent()
        assert result is True
        mock_call.assert_called_once_with(["/usr/bin/pkill", "-HUP", "yubikey-agent"])
        mock_sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize("platform", ["linux", "darwin", "freebsd"])
def test_kill_yubikey_agent_failure(platform):
    with (
        patch("ykman.pcsc.sys.platform", platform),
        patch("ykman.pcsc.shutil.which", return_value="/usr/bin/pkill"),
        patch("ykman.pcsc.os.path.exists", return_value=True),
        patch("ykman.pcsc.subprocess.call", return_value=1) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        result = kill_yubikey_agent()
        assert result is False
        mock_call.assert_called_once_with(["/usr/bin/pkill", "-HUP", "yubikey-agent"])
        mock_sleep.assert_not_called()


def test_kill_yubikey_agent_windows():
    with (
        patch("ykman.pcsc.sys.platform", "win32"),
        patch("ykman.pcsc.subprocess.call") as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        result = kill_yubikey_agent()
        assert result is False
        mock_call.assert_not_called()
        mock_sleep.assert_not_called()


@pytest.mark.parametrize("platform", ["linux", "darwin", "freebsd"])
def test_kill_scdaemon_non_win_success(platform):
    with (
        patch("ykman.pcsc.sys.platform", platform),
        patch("ykman.pcsc.shutil.which", return_value="/usr/bin/pkill"),
        patch("ykman.pcsc.os.path.exists", return_value=True),
        patch("ykman.pcsc.subprocess.call", return_value=0) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        result = kill_scdaemon()
        assert result is True
        mock_call.assert_called_once_with(["/usr/bin/pkill", "-9", "scdaemon"])
        mock_sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize("platform", ["linux", "darwin", "freebsd"])
def test_kill_scdaemon_non_win_failure(platform):
    with (
        patch("ykman.pcsc.sys.platform", platform),
        patch("ykman.pcsc.shutil.which", return_value="/usr/bin/pkill"),
        patch("ykman.pcsc.os.path.exists", return_value=True),
        patch("ykman.pcsc.subprocess.call", return_value=1) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        result = kill_scdaemon()
        assert result is False
        mock_call.assert_called_once_with(["/usr/bin/pkill", "-9", "scdaemon"])
        mock_sleep.assert_not_called()


def test_kill_scdaemon_windows():
    mock_p = MagicMock()

    def get_property(name):
        prop = MagicMock()
        if name == "Name":
            prop.Value = "scdaemon.exe"
        elif name == "ProcessID":
            prop.Value = 1234
        return prop

    mock_p.Properties_.side_effect = get_property

    mock_wmi = MagicMock()
    mock_wmi.InstancesOf.return_value = [mock_p]

    mock_win32api = MagicMock()
    mock_win32com = MagicMock()
    mock_win32com.client.GetObject.return_value = mock_wmi

    with (
        patch("ykman.pcsc.sys.platform", "win32"),
        patch("ykman.pcsc.sleep") as mock_sleep,
        patch.dict(
            "sys.modules",
            {
                "win32api": mock_win32api,
                "win32com": mock_win32com,
                "win32com.client": mock_win32com.client,
            },
        ),
    ):
        result = kill_scdaemon()
        assert result is True
        mock_win32api.OpenProcess.assert_called_once_with(1, False, 1234)
        mock_win32api.TerminateProcess.assert_called_once_with(
            mock_win32api.OpenProcess.return_value, -1
        )
        mock_win32api.CloseHandle.assert_called_once_with(
            mock_win32api.OpenProcess.return_value
        )
        mock_sleep.assert_called_once_with(0.1)


def test_kill_scdaemon_windows_no_process():
    mock_p = MagicMock()

    def get_property(name):
        prop = MagicMock()
        if name == "Name":
            prop.Value = "other.exe"
        return prop

    mock_p.Properties_.side_effect = get_property

    mock_wmi = MagicMock()
    mock_wmi.InstancesOf.return_value = [mock_p]

    mock_win32api = MagicMock()
    mock_win32com = MagicMock()
    mock_win32com.client.GetObject.return_value = mock_wmi

    with (
        patch("ykman.pcsc.sys.platform", "win32"),
        patch("ykman.pcsc.sleep") as mock_sleep,
        patch.dict(
            "sys.modules",
            {
                "win32api": mock_win32api,
                "win32com": mock_win32com,
                "win32com.client": mock_win32com.client,
            },
        ),
    ):
        result = kill_scdaemon()
        assert result is False
        mock_win32api.OpenProcess.assert_not_called()
        mock_sleep.assert_not_called()
