"""
WebAuthn credProps + minPinLength extensions.

credProps (credential properties):
  A client-side extension that tells the relying party whether the
  credential was actually stored as a resident (discoverable) key.
  The authenticator does not participate - the client fills this in.

minPinLength:
  Requests the authenticator to report the minimum PIN length it
  enforces.  The RP can use this to guide users.

Usage: uv run python examples/webauthn_cred_props.py

⚠ This example creates credentials on the authenticator.
"""

from __future__ import annotations

import json
import os

from example_utils import RP_ID, b64url, open_client


def main() -> None:
    client = open_client()

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
