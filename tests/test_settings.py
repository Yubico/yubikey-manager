import os
import stat
import pytest
from ykman.settings import Settings, AppData


def test_settings_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(Settings, "_config_dir", str(tmp_path))

    settings = Settings("test_settings")
    settings["key"] = "value"
    settings.write()

    assert settings.fname.is_file()
    if os.name == "posix":
        mode = settings.fname.stat().st_mode
        dir_mode = settings.fname.parent.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
        assert stat.S_IMODE(dir_mode) == 0o700


def test_appdata_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(AppData, "_config_dir", str(tmp_path))

    appdata = AppData("test_appdata")
    appdata["key"] = "value"
    appdata.write()

    assert appdata.fname.is_file()
    if os.name == "posix":
        mode = appdata.fname.stat().st_mode
        dir_mode = appdata.fname.parent.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
        assert stat.S_IMODE(dir_mode) == 0o700


def test_settings_permissions_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(Settings, "_config_dir", str(tmp_path))

    settings = Settings("test_settings_fail")
    # Non-serializable object triggers TypeError during json.dump
    settings["key"] = object()

    with pytest.raises(TypeError):
        settings.write()

    if os.name == "posix":
        assert settings.fname.is_file()
        mode = settings.fname.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600


def test_settings_overwrite_existing_loose_permissions_on_failure(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(Settings, "_config_dir", str(tmp_path))

    settings_file = tmp_path / "test_settings_loose.json"
    settings_file.write_text("{}")
    if os.name == "posix":
        os.chmod(settings_file, 0o644)

    settings = Settings("test_settings_loose")
    settings["key"] = object()  # Non-serializable object triggers TypeError

    with pytest.raises(TypeError):
        settings.write()

    if os.name == "posix":
        mode = settings_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
