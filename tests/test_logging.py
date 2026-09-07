import os
import stat
from ykman.logging import init_logging
from yubikit.logging import LOG_LEVEL


def test_log_file_permissions(tmp_path):
    log_file = tmp_path / "test.log"
    init_logging(LOG_LEVEL.DEBUG, log_file=str(log_file), replace=True)

    assert log_file.is_file()
    if os.name == "posix":
        mode = log_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600


def test_existing_log_file_permissions_tightened(tmp_path):
    log_file = tmp_path / "existing.log"
    # Create file with loose permissions first
    log_file.write_text("initial content\n")
    if os.name == "posix":
        os.chmod(log_file, 0o644)

    init_logging(LOG_LEVEL.DEBUG, log_file=str(log_file), replace=True)

    assert log_file.is_file()
    if os.name == "posix":
        mode = log_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
