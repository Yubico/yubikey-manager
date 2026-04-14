import os
import sys

from ykman._find_ykman import find_ykman_bin


def _run() -> None:
    ykman = find_ykman_bin()

    if sys.platform == "win32":
        import subprocess

        try:
            completed_process = subprocess.run([ykman, *sys.argv[1:]])  # noqa: S603
        except KeyboardInterrupt:
            sys.exit(2)
        sys.exit(completed_process.returncode)
    else:
        os.execvp(ykman, [ykman, *sys.argv[1:]])  # noqa: S606


if __name__ == "__main__":
    _run()
