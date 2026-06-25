#!/usr/bin/env python3
"""Cross-vendor route selection for the repo-local Cato runner."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import os
import sys
from typing import Mapping


if sys.version_info < (3, 12):
    raise SystemExit("cross_vendor_router.py requires Python >= 3.12")


Vendor = str

OPENAI_MODEL = "gpt-5.5"
ANTHROPIC_MODEL = "claude-opus-4-8"


@dataclass(frozen=True)
class CrossVendorRoute:
    current_vendor: Vendor
    engineer_vendor: Vendor
    reviewer_vendor: Vendor
    engineer_model: str
    reviewer_model: str
    engineer_harness: str
    reviewer_harness: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def normalize_vendor(value: str | None) -> Vendor | None:
    if not value:
        return None
    lower = value.strip().lower()
    if (
        lower in {"openai", "gpt", "gpt5", "gpt-5.5", "codex"}
        or "openai" in lower
        or "gpt-5.5" in lower
        or "codex" in lower
    ):
        return "openai"
    if (
        lower in {"anthropic", "claude", "opus", "opus4.8", "claude-opus-4-8"}
        or "anthropic" in lower
        or "claude" in lower
        or "opus" in lower
    ):
        return "anthropic"
    return None


def detect_current_vendor(env: Mapping[str, str] | None = None) -> Vendor | None:
    env = os.environ if env is None else env
    explicit = normalize_vendor(env.get("PAI_CURRENT_VENDOR") or env.get("PAI_AUTHOR_VENDOR"))
    if explicit:
        return explicit

    for key in (
        "OPENCODE_MODEL",
        "OPENCODE_PROVIDER",
        "OPENAI_MODEL",
        "CODEX_MODEL",
        "ANTHROPIC_MODEL",
        "CLAUDE_MODEL",
        "CLAUDE_CODE_MODEL",
        "COPILOT_MODEL",
        "COPILOT_AGENT_MODEL",
    ):
        vendor = normalize_vendor(env.get(key))
        if vendor:
            return vendor

    if env.get("OPENCODE") or env.get("OPENCODE_SESSION") or env.get("CODEX_SESSION_ID"):
        return "openai"
    if env.get("CLAUDECODE") or env.get("CLAUDE_CODE") or env.get("ANTHROPIC_DEFAULT_OPUS_MODEL"):
        return "anthropic"

    return None


def opposite_vendor(vendor: Vendor) -> Vendor:
    if vendor == "openai":
        return "anthropic"
    if vendor == "anthropic":
        return "openai"
    raise ValueError(f"Unknown vendor: {vendor}")


def model_for(vendor: Vendor) -> str:
    if vendor == "openai":
        return OPENAI_MODEL
    if vendor == "anthropic":
        return ANTHROPIC_MODEL
    raise ValueError(f"Unknown vendor: {vendor}")


def harness_for(vendor: Vendor) -> str:
    if vendor == "openai":
        return "codex"
    if vendor == "anthropic":
        return "claude"
    raise ValueError(f"Unknown vendor: {vendor}")


def resolve_cross_vendor_route(
    current_vendor: str | None = None,
    auditor_vendor: str | None = None,
    env: Mapping[str, str] | None = None,
) -> CrossVendorRoute:
    current = normalize_vendor(current_vendor) or detect_current_vendor(env)
    if not current:
        raise ValueError(
            "Unable to detect current vendor. Pass --current-vendor openai|anthropic "
            "or set PAI_CURRENT_VENDOR."
        )

    reviewer = normalize_vendor(auditor_vendor) or opposite_vendor(current)
    if reviewer == current:
        raise ValueError(
            f"Cross-vendor route invalid: reviewer vendor {reviewer} matches current vendor {current}."
        )

    return CrossVendorRoute(
        current_vendor=current,
        engineer_vendor=current,
        reviewer_vendor=reviewer,
        engineer_model=model_for(current),
        reviewer_model=model_for(reviewer),
        engineer_harness="current",
        reviewer_harness=harness_for(reviewer),
    )


def _arg_value(args: list[str], names: set[str]) -> str | None:
    for idx, arg in enumerate(args):
        if arg in names and idx + 1 < len(args):
            return args[idx + 1]
        for name in names:
            prefix = f"{name}="
            if arg.startswith(prefix):
                return arg[len(prefix) :]
    return None


def main(argv: list[str]) -> int:
    try:
        route = resolve_cross_vendor_route(
            current_vendor=_arg_value(argv, {"--current-vendor", "--author-vendor"}),
            auditor_vendor=_arg_value(argv, {"--auditor-vendor", "--reviewer-vendor"}),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(route.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
