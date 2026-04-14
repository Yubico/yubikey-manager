"""
WebAuthn credProtect extension – set credential protection level.

Demonstrates creating a credential with each of the three credProtect
protection levels and inspecting the echoed policy in the response.

Protection levels:
  Level 1 - userVerificationOptional (default, no extra protection)
  Level 2 - userVerificationOptionalWithCredentialIDList
  Level 3 - userVerificationRequired

Usage: uv run python examples/webauthn_cred_protect.py

⚠ This example creates credentials on the authenticator.
"""

from __future__ import annotations

import json
import os

from example_utils import RP_ID, b64url, open_client


def main() -> None:
    client = open_client()

    policies = [
        (
            "userVerificationOptional",
            "Level 1 - userVerificationOptional",
        ),
        (
            "userVerificationOptionalWithCredentialIDList",
            "Level 2 - userVerificationOptionalWithCredentialIDList",
        ),
        (
            "userVerificationRequired",
            "Level 3 - userVerificationRequired",
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
