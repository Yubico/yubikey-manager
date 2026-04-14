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
import json
import os

from example_utils import RP_ID, b64url, open_client


def main() -> None:
    client = open_client()

    # -- Registration --
    print("\n━━━ Registration ━━━")

    challenge = os.urandom(32)
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

    # -- Authentication --
    print("\n━━━ Authentication ━━━")

    challenge = os.urandom(32)
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

    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
