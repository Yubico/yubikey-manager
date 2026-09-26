## 2025-02-22 - POSIX File Creation Permission Race Condition
**Vulnerability:** Settings and AppData files were opened with default mode (`open("w")`) and permissions tightened via `chmod(0o600)` only after writing completed. This allowed temporary world/group read access and left files un-chmod'd if writing failed.
**Learning:** `Path.open("w")` creates files using default umask before `chmod` runs.
**Prevention:** On POSIX, use `os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)` and `os.fdopen` to enforce restrictive file permissions atomically at creation time.
