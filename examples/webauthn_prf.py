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
import json
import os

from example_utils import RP_ID, b64url, open_client


def main() -> None:
    client = open_client()

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

    # -- Second authentication with same salt -> same secret --
    print("\n━━━ Verify determinism (same salt -> same secret) ━━━")

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
        print("❌ Secrets differ - this is unexpected!")

    client.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
