#!/usr/bin/env python3
"""Reject commits that accidentally stage local/runtime workflow artifacts."""

from __future__ import annotations

import subprocess
import sys


if sys.version_info < (3, 12):
    raise SystemExit("check_commit_safety.py requires Python >= 3.12")


BLOCKED_PATHS = {
    "docs/yubikit/OPERATOR_CONTEXT.local.md",
    ".github/state/cato-quota.json",
    ".github/verification/cato-findings.jsonl",
}


def staged_files() -> list[str] | None:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr.strip() or "failed to inspect staged files", file=sys.stderr)
        return None
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    staged = staged_files()
    if staged is None:
        return 1
    blocked = sorted(path for path in staged if path in BLOCKED_PATHS)
    if blocked:
        print("Refusing to proceed: local/runtime workflow artifacts are staged:", file=sys.stderr)
        for path in blocked:
            print(f"- {path}", file=sys.stderr)
        print("Unstage these files unless the Operator explicitly approved committing them.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
