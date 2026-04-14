"""
WebAuthn credProtect extension – set credential protection level.

Demonstrates creating a credential with each of the three credProtect
protection levels and inspecting the echoed policy in the response.

Protection levels:
  Level 1 – userVerificationOptional (default, no extra protection)
  Level 2 – userVerificationOptionalWithCredentialIDList
  Level 3 – userVerificationRequired

Usage: uv run python examples/webauthn_cred_protect.py

⚠ This example creates credentials on the authenticator.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import sys

from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.device import list_all_devices
from yubikit.webauthn import ClientDataCollector, UserInteraction, WebAuthnClient

ORIGIN = "https://example.com"
RP_ID = "example.com"


class ConsoleInteraction(UserInteraction):
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
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main() -> None:
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
        print("No usable connection.", file=sys.stderr)
        sys.exit(1)

    client = WebAuthnClient(conn, ConsoleInteraction(), SimpleCollector())

    policies = [
        (
            "userVerificationOptional",
            "Level 1 – userVerificationOptional",
        ),
        (
            "userVerificationOptionalWithCredentialIDList",
            "Level 2 – userVerificationOptionalWithCredentialIDList",
        ),
        (
            "userVerificationRequired",
            "Level 3 – userVerificationRequired",
        ),
    ]

    for policy, label in policies:
        print(f"\n━━━ {label} ━━━")

        try:
            reg_json = client.make_credential(
                json.dumps(
                    {
                        "rp": {"name": "CredProtect Example", "id": RP_ID},
                        "user": {
                            "id": b64url(f"user-cp-{policy}".encode()),
                            "name": "credprotect@example.com",
                            "displayName": "CredProtect User",
                        },
                        "challenge": b64url(os.urandom(32)),
                        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                        "timeout": 60000,
                        "extensions": {
                            "credentialProtectionPolicy": policy,
                            "enforceCredentialProtectionPolicy": True,
                        },
                    }
                )
            )

            reg = json.loads(reg_json)
            print(f"  ✅ Credential: {reg['id']}")
            ext = reg.get("clientExtensionResults", {})
            cp = ext.get("credProtect", {})
            if cp:
                print(f"  Echoed policy: {cp.get('policy')}")
            else:
                print("  (no credProtect in response)")
        except Exception as e:
            print(f"  ❌ Failed: {e}")

    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
