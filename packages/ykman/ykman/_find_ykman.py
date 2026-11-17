from __future__ import annotations

import os
import sys
import sysconfig


class YkmanNotFound(FileNotFoundError): ...


def find_ykman_bin() -> str:
    """Return the ykman binary path."""

    ykman_exe = "ykman" + sysconfig.get_config_var("EXE")

    targets = [
        sysconfig.get_path("scripts"),
        sysconfig.get_path("scripts", vars={"base": sys.base_prefix}),
    ]

    seen = []
    for target in targets:
        if not target:
            continue
        if target in seen:
            continue
        seen.append(target)
        path = os.path.join(target, ykman_exe)
        if os.path.isfile(path):
            return path

    locations = "\n".join(f" - {target}" for target in seen)
    raise YkmanNotFound(
        f"Could not find the ykman binary in any of the following locations:\n"
        f"{locations}\n"
    )
