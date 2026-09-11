from unittest.mock import MagicMock, patch

from ykman.diagnostics import sys_info


def test_sys_info_non_win32():
    with patch("sys.platform", "linux"), patch("os.getuid", return_value=1000):
        info = sys_info()

        assert "ykman" in info
        assert "Python" in info
        assert info["Platform"] == "linux"
        assert "Arch" in info
        assert "System date" in info
        assert info["Running as admin"] is False
        assert "Windows version" not in info


def test_sys_info_non_win32_root():
    with patch("sys.platform", "linux"), patch("os.getuid", return_value=0):
        info = sys_info()

        assert info["Platform"] == "linux"
        assert info["Running as admin"] is True


def test_sys_info_win32_admin():
    mock_windll = MagicMock()
    mock_windll.shell32.IsUserAnAdmin.return_value = 1

    with (
        patch("sys.platform", "win32"),
        patch("ctypes.windll", mock_windll, create=True),
        patch("ykman.diagnostics.get_windows_version", return_value="10.0.19041"),
    ):
        info = sys_info()

        assert info["Platform"] == "win32"
        assert info["Running as admin"] is True
        assert info["Windows version"] == "10.0.19041"


def test_sys_info_win32_non_admin():
    mock_windll = MagicMock()
    mock_windll.shell32.IsUserAnAdmin.return_value = 0

    with (
        patch("sys.platform", "win32"),
        patch("ctypes.windll", mock_windll, create=True),
        patch("ykman.diagnostics.get_windows_version", return_value="10.0.19041"),
    ):
        info = sys_info()

        assert info["Platform"] == "win32"
        assert info["Running as admin"] is False
        assert info["Windows version"] == "10.0.19041"
