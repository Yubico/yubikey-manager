#!/usr/bin/env python3
"""Install a local pre-commit hook for Yubikit workflow commit safety."""

from __future__ import annotations

from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / ".git" / "hooks" / "pre-commit"
MARKER = "# yubikit-workflow-commit-safety"
END_MARKER = "# end-yubikit-workflow-commit-safety"
BLOCK = f"""{MARKER}
if command -v py >/dev/null 2>&1; then
  py -3.12 .github/tools/check_commit_safety.py || exit 1
elif command -v python3 >/dev/null 2>&1; then
  python3 .github/tools/check_commit_safety.py || exit 1
else
  python .github/tools/check_commit_safety.py || exit 1
fi
{END_MARKER}
"""


def remove_existing_block(text: str) -> str:
    lines = text.splitlines()
    kept: list[str] = []
    skipping = False
    for line in lines:
        if line == MARKER:
            skipping = True
            continue
        if skipping:
            if line == END_MARKER:
                skipping = False
            continue
        kept.append(line)
    return "\n".join(kept).rstrip() + "\n"


def main() -> int:
    HOOK.parent.mkdir(parents=True, exist_ok=True)
    existing = HOOK.read_text(encoding="utf-8") if HOOK.exists() else "#!/bin/sh\n"
    existing = remove_existing_block(existing)
    HOOK.write_text(existing + "\n" + BLOCK, encoding="utf-8")
    mode = HOOK.stat().st_mode
    HOOK.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed Yubikit commit safety hook: {HOOK}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
