"""
WebAuthn registration + authentication using a FIDO2 security key.

Demonstrates:
  1. Discovering a YubiKey via ykman
  2. Creating a WebAuthnClient with console-based interaction
  3. Performing a registration ceremony (make_credential)
  4. Using the resulting credential to perform authentication (get_assertion)

The credential is created as a non-resident key for "example.com".
PIN entry is prompted on stdin when required.

Usage: uv run python examples/webauthn.py

⚠ This example creates a (non-resident) credential on the authenticator.
  It does NOT delete it afterwards.
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
        challenge = options["challenge"]
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        return client_data, rp_id

    def collect_get(self, options_json: str) -> tuple[bytes, str]:
        options = json.loads(options_json)
        rp_id = options.get("rpId", RP_ID)
        challenge = options["challenge"]
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        return client_data, rp_id


def random_challenge() -> bytes:
    """Generate a random challenge (32 bytes)."""
    return os.urandom(32)


def b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main() -> None:
    # 1. Find a YubiKey
    devices = list_all_devices()
    if not devices:
        print("No YubiKeys found.", file=sys.stderr)
        sys.exit(1)

    dev, info = devices[0]
    print(f"Using: {info.serial or 'Unknown serial'}")

    # 2. Open connection (prefer FIDO HID, fall back to CCID)
    conn: FidoConnection | SmartCardConnection
    if dev.supports_connection(FidoConnection):  # type: ignore[arg-type]
        print("  Using FIDO HID transport")
        conn = dev.open_connection(FidoConnection)  # type: ignore[arg-type]
    elif dev.supports_connection(SmartCardConnection):
        print("  Using CCID transport")
        conn = dev.open_connection(SmartCardConnection)
    else:
        print("  No usable connection available.", file=sys.stderr)
        sys.exit(1)

    # 3. Create WebAuthn client
    client = WebAuthnClient(conn, ConsoleInteraction(), SimpleCollector())

    # 4. Registration ceremony
    print("\n━━━ Registration ━━━")

    challenge = random_challenge()
    create_options = json.dumps(
        {
            "rp": {
                "name": "Example RP",
                "id": RP_ID,
            },
            "user": {
                "id": b64url(b"user-1234"),
                "name": "alice@example.com",
                "displayName": "Alice",
            },
            "challenge": b64url(challenge),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -8},  # EdDSA
            ],
            "timeout": 60000,
        }
    )

    reg_json = client.make_credential(create_options)
    reg = json.loads(reg_json)

    cred_id_b64 = reg["id"]
    cred_id = base64.urlsafe_b64decode(cred_id_b64 + "==")
    print("✅ Registration succeeded!")
    print(f"  Credential ID: {cred_id.hex()} ({len(cred_id)} bytes)")
    att_obj = base64.urlsafe_b64decode(reg["response"]["attestationObject"] + "==")
    print(f"  Attestation object: {len(att_obj)} bytes")

    # 5. Authentication ceremony
    print("\n━━━ Authentication ━━━")

    challenge = random_challenge()
    get_options = json.dumps(
        {
            "challenge": b64url(challenge),
            "timeout": 60000,
            "rpId": RP_ID,
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": cred_id_b64,
                }
            ],
            "userVerification": "discouraged",
        }
    )

    assertions_json = client.get_assertion(get_options)
    print(f"✅ Authentication succeeded! ({len(assertions_json)} assertion(s))")

    for i, assertion_json in enumerate(assertions_json):
        assertion = json.loads(assertion_json)
        aid = base64.urlsafe_b64decode(assertion["id"] + "==")
        sig = base64.urlsafe_b64decode(assertion["response"]["signature"] + "==")
        auth_data = base64.urlsafe_b64decode(
            assertion["response"]["authenticatorData"] + "=="
        )
        print(f"  Assertion {i}:")
        print(f"    Credential ID: {aid.hex()}")
        print(f"    Signature: {len(sig)} bytes")
        print(f"    Auth data: {len(auth_data)} bytes")
        user_handle = assertion["response"].get("userHandle")
        if user_handle:
            uh = base64.urlsafe_b64decode(user_handle + "==")
            print(f"    User handle: {uh.hex()}")

    # Release the connection
    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
