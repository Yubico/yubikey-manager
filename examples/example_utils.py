"""Shared utilities for WebAuthn examples.

Provides console-based UserInteraction, a simple ClientDataCollector,
device discovery, and helper functions used across all examples.
"""

from __future__ import annotations

import base64
import getpass
import json
import sys

from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.device import list_all_devices
from yubikit.webauthn import ClientDataCollector, UserInteraction, WebAuthnClient

ORIGIN = "https://example.com"
RP_ID = "example.com"


class ConsoleInteraction(UserInteraction):
    """Console-based user interaction for PIN/UV prompts."""

    def prompt_up(self) -> None:
        print("\n👆 Touch your security key...")

    def request_pin(self, permissions: int, rp_id: str | None) -> str | None:
        try:
            pin = getpass.getpass("🔑 Enter PIN: ")
            return pin if pin else None
        except (EOFError, KeyboardInterrupt):
            return None

    def request_uv(self, permissions: int, rp_id: str | None) -> bool:
        print("🔒 Biometric verification requested - proceeding")
        return True


class SimpleCollector(ClientDataCollector):
    """Simple client data collector for example.com."""

    def collect_create(self, options_json: str) -> tuple[bytes, str]:
        options = json.loads(options_json)
        rp_id = options.get("rp", {}).get("id", RP_ID)
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": options["challenge"],
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        return client_data, rp_id

    def collect_get(self, options_json: str) -> tuple[bytes, str]:
        options = json.loads(options_json)
        rp_id = options.get("rpId", RP_ID)
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": options["challenge"],
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        return client_data, rp_id


def b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def open_client() -> WebAuthnClient:
    """Discover a YubiKey and create a WebAuthnClient.

    Prints device information and exits the process if no device is found.
    """
    devices = list_all_devices()
    if not devices:
        print("No YubiKeys found.", file=sys.stderr)
        sys.exit(1)

    dev, info = devices[0]
    print(f"Using: {info.serial or 'Unknown serial'}")

    conn: FidoConnection | SmartCardConnection
    if dev.supports_connection(FidoConnection):  # type: ignore[arg-type]
        conn = dev.open_connection(FidoConnection)  # type: ignore[arg-type]
    elif dev.supports_connection(SmartCardConnection):
        conn = dev.open_connection(SmartCardConnection)
    else:
        print("No usable connection available.", file=sys.stderr)
        sys.exit(1)

    return WebAuthnClient(conn, ConsoleInteraction(), SimpleCollector())
