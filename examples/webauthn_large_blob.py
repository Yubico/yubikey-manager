"""
WebAuthn largeBlob extension – read and write large blobs.

Demonstrates:
  1. Creating a credential with largeBlob support required
  2. Writing arbitrary data to the large blob associated with the credential
  3. Reading the data back in a subsequent authentication

Unlike credBlob (which is limited to ~32 bytes), largeBlob can store
much larger data using the authenticator's dedicated blob storage.

Usage: uv run python examples/webauthn_large_blob.py

⚠ This example creates a credential and writes to large blob storage.
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

    # -- Registration with largeBlob support required --
    # largeBlob requires a resident key (discoverable credential)
    print("\n━━━ Registration (largeBlob: required) ━━━")

    reg_json = client.make_credential(
        json.dumps(
            {
                "rp": {"name": "LargeBlob Example", "id": RP_ID},
                "user": {
                    "id": b64url(b"largeblob-user"),
                    "name": "largeblob@example.com",
                    "displayName": "LargeBlob User",
                },
                "challenge": b64url(os.urandom(32)),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "authenticatorSelection": {
                    "residentKey": "required",
                },
                "extensions": {
                    "largeBlob": {"support": "required"},
                },
            }
        )
    )

    reg = json.loads(reg_json)
    cred_id = reg["id"]
    print(f"✅ Credential: {cred_id}")

    ext = reg.get("clientExtensionResults", {})
    lb = ext.get("largeBlob", {})
    if lb:
        print(f"  largeBlob supported: {lb.get('supported')}")

    # -- Write a blob --
    blob_data = (
        b"This is a larger piece of data stored via the largeBlob extension. "
        b"It can hold more than the 32 bytes credBlob is limited to."
    )
    print(f"\n━━━ Authentication: write blob ({len(blob_data)} bytes) ━━━")

    assertions = client.get_assertion(
        json.dumps(
            {
                "challenge": b64url(os.urandom(32)),
                "timeout": 60000,
                "rpId": RP_ID,
                "allowCredentials": [{"type": "public-key", "id": cred_id}],
                "userVerification": "discouraged",
                "extensions": {
                    "largeBlob": {"write": b64url(blob_data)},
                },
            }
        )
    )

    a = json.loads(assertions[0])
    ext = a.get("clientExtensionResults", {})
    lb = ext.get("largeBlob", {})
    if lb:
        print(f"✅ Blob written: {lb.get('written')}")

    # -- Read the blob back --
    print("\n━━━ Authentication: read blob ━━━")

    assertions = client.get_assertion(
        json.dumps(
            {
                "challenge": b64url(os.urandom(32)),
                "timeout": 60000,
                "rpId": RP_ID,
                "allowCredentials": [{"type": "public-key", "id": cred_id}],
                "userVerification": "discouraged",
                "extensions": {
                    "largeBlob": {"read": True},
                },
            }
        )
    )

    a = json.loads(assertions[0])
    ext = a.get("clientExtensionResults", {})
    lb = ext.get("largeBlob", {})
    if lb and lb.get("blob"):
        data = base64.urlsafe_b64decode(lb["blob"] + "==")
        print(f"✅ Read {len(data)} bytes")
        try:
            print(f'  Content: "{data.decode()}"')
        except UnicodeDecodeError:
            print(f"  Content: {data.hex()}")
        if data == blob_data:
            print("  ✅ Data matches what was written!")
        else:
            print("  ❌ Data does not match!")
    else:
        print("  (no blob data returned)")

    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
