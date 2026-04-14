"""
WebAuthn credProps + minPinLength extensions.

credProps (credential properties):
  A client-side extension that tells the relying party whether the
  credential was actually stored as a resident (discoverable) key.
  The authenticator does not participate – the client fills this in.

minPinLength:
  Requests the authenticator to report the minimum PIN length it
  enforces.  The RP can use this to guide users.

Usage: uv run python examples/webauthn_cred_props.py

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

    # -- Non-resident credential with credProps --
    print("\n━━━ Non-resident credential (credProps) ━━━")

    reg_json = client.make_credential(
        json.dumps(
            {
                "rp": {"name": "CredProps Example", "id": RP_ID},
                "user": {
                    "id": b64url(b"props-user-nr"),
                    "name": "props@example.com",
                    "displayName": "Props User",
                },
                "challenge": b64url(os.urandom(32)),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "authenticatorSelection": {
                    "residentKey": "discouraged",
                },
                "extensions": {
                    "credProps": True,
                    "minPinLength": True,
                },
            }
        )
    )

    reg = json.loads(reg_json)
    print(f"✅ Credential: {reg['id']}")
    ext = reg.get("clientExtensionResults", {})
    cp = ext.get("credProps", {})
    if cp:
        print(f"  Discoverable (rk): {cp.get('rk')}")
    mp = ext.get("minPinLength", {})
    if mp:
        print(f"  Min PIN length: {mp.get('length')}")

    # -- Resident credential with credProps --
    print("\n━━━ Resident credential (credProps) ━━━")

    reg_json = client.make_credential(
        json.dumps(
            {
                "rp": {"name": "CredProps Example", "id": RP_ID},
                "user": {
                    "id": b64url(b"props-user-rk"),
                    "name": "props-rk@example.com",
                    "displayName": "Props RK User",
                },
                "challenge": b64url(os.urandom(32)),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "authenticatorSelection": {
                    "residentKey": "required",
                },
                "extensions": {
                    "credProps": True,
                    "minPinLength": True,
                },
            }
        )
    )

    reg = json.loads(reg_json)
    print(f"✅ Credential: {reg['id']}")
    ext = reg.get("clientExtensionResults", {})
    cp = ext.get("credProps", {})
    if cp:
        print(f"  Discoverable (rk): {cp.get('rk')}")
    mp = ext.get("minPinLength", {})
    if mp:
        print(f"  Min PIN length: {mp.get('length')}")

    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
