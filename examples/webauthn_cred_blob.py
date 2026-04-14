"""
WebAuthn credBlob extension – store and retrieve a small blob.

Demonstrates:
  1. Creating a credential with credBlob to store a small secret
  2. Authenticating with getCredBlob: true to read the blob back

credBlob stores data directly in the credential (typically max 32 bytes).
It is simpler than largeBlob but limited in size.

Usage: uv run python examples/webauthn_cred_blob.py

⚠ This example creates a credential on the authenticator.
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

    # -- Registration: store a blob --
    blob_data = b"hello, credBlob!"
    print(f"\n━━━ Registration (credBlob: {len(blob_data)} bytes) ━━━")

    reg_json = client.make_credential(
        json.dumps(
            {
                "rp": {"name": "CredBlob Example", "id": RP_ID},
                "user": {
                    "id": b64url(b"blob-user"),
                    "name": "blob@example.com",
                    "displayName": "Blob User",
                },
                "challenge": b64url(os.urandom(32)),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "extensions": {
                    "credBlob": b64url(blob_data),
                },
            }
        )
    )

    reg = json.loads(reg_json)
    cred_id = reg["id"]
    print(f"✅ Credential: {cred_id}")

    ext = reg.get("clientExtensionResults", {})
    cb = ext.get("credBlob", {})
    if cb:
        print(f"  Blob stored: {cb.get('stored')}")

    # -- Authentication: retrieve the blob --
    print("\n━━━ Authentication (getCredBlob) ━━━")

    assertions = client.get_assertion(
        json.dumps(
            {
                "challenge": b64url(os.urandom(32)),
                "timeout": 60000,
                "rpId": RP_ID,
                "allowCredentials": [{"type": "public-key", "id": cred_id}],
                "userVerification": "discouraged",
                "extensions": {
                    "getCredBlob": True,
                },
            }
        )
    )

    a = json.loads(assertions[0])
    print("✅ Authentication succeeded")

    ext = a.get("clientExtensionResults", {})
    cb = ext.get("credBlob", {})
    if cb:
        blob_b64 = cb.get("blob", "")
        retrieved = base64.urlsafe_b64decode(blob_b64 + "==")
        print(f"  Retrieved blob: {retrieved.hex()}")
        try:
            print(f'  As UTF-8: "{retrieved.decode()}"')
        except UnicodeDecodeError:
            print("  (not valid UTF-8)")

    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
