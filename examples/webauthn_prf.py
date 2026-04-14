"""
WebAuthn PRF extension – derive symmetric secrets from a credential.

Demonstrates:
  1. Registering a credential with the PRF extension enabled
  2. Deriving a secret during authentication using eval salts
  3. Verifying that the same salts produce the same secret

The PRF extension wraps the CTAP2 hmac-secret extension.  The client
hashes application-supplied inputs through
  SHA-256("WebAuthn PRF\\0" || input)
before sending them to the authenticator as HMAC salts.

Usage: uv run python examples/webauthn_prf.py

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

    # -- Registration with PRF enabled --
    print("\n━━━ Registration (PRF) ━━━")

    salt_input = b64url(b"example PRF salt input")

    reg_json = client.make_credential(
        json.dumps(
            {
                "rp": {"name": "PRF Example", "id": RP_ID},
                "user": {
                    "id": b64url(b"prf-user"),
                    "name": "prf@example.com",
                    "displayName": "PRF User",
                },
                "challenge": b64url(os.urandom(32)),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "extensions": {"prf": {}},
            }
        )
    )

    reg = json.loads(reg_json)
    cred_id = reg["id"]
    print(f"✅ Credential: {cred_id}")

    ext = reg.get("clientExtensionResults", {})
    prf_out = ext.get("prf", {})
    if prf_out:
        print(f"  PRF enabled: {prf_out.get('enabled')}")

    # -- Authentication with PRF eval --
    print("\n━━━ Authentication (PRF eval) ━━━")

    assertions = client.get_assertion(
        json.dumps(
            {
                "challenge": b64url(os.urandom(32)),
                "timeout": 60000,
                "rpId": RP_ID,
                "allowCredentials": [{"type": "public-key", "id": cred_id}],
                "userVerification": "discouraged",
                "extensions": {
                    "prf": {
                        "eval": {
                            "first": salt_input,
                        }
                    }
                },
            }
        )
    )

    a1 = json.loads(assertions[0])
    print("✅ Authentication succeeded")
    ext1 = a1.get("clientExtensionResults", {})
    prf1 = ext1.get("prf", {}).get("results", {})
    secret1 = prf1.get("first", "")
    s1_bytes = base64.urlsafe_b64decode(secret1 + "==") if secret1 else b""
    if secret1:
        print(f"  PRF first: {s1_bytes.hex()} ({len(s1_bytes)} bytes)")

    # -- Second authentication with same salt → same secret --
    print("\n━━━ Verify determinism (same salt → same secret) ━━━")

    assertions2 = client.get_assertion(
        json.dumps(
            {
                "challenge": b64url(os.urandom(32)),
                "timeout": 60000,
                "rpId": RP_ID,
                "allowCredentials": [{"type": "public-key", "id": cred_id}],
                "userVerification": "discouraged",
                "extensions": {
                    "prf": {
                        "eval": {
                            "first": salt_input,
                        }
                    }
                },
            }
        )
    )

    a2 = json.loads(assertions2[0])
    ext2 = a2.get("clientExtensionResults", {})
    secret2 = ext2.get("prf", {}).get("results", {}).get("first", "")

    if secret1 and secret2 and secret1 == secret2:
        print(f"✅ Same salt produced the same secret ({len(s1_bytes)} bytes)")
    else:
        print("❌ Secrets differ – this is unexpected!")

    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
