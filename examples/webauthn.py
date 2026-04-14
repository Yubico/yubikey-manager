"""
WebAuthn registration + authentication using a FIDO2 security key.

Demonstrates:
  1. Discovering a FIDO HID device
  2. Creating a WebAuthnClient with console-based interaction
  3. Performing a registration ceremony (make_credential)
  4. Using the resulting credential to perform authentication (get_assertion)

The credential is created as a non-resident key for "example.com".
PIN entry is prompted on stdin when required.

Usage: uv run python examples/webauthn.py

⚠ This example creates a (non-resident) credential on the authenticator.
  It does NOT delete it afterwards.
"""

import base64
import getpass
import json
import os
import sys

from _yubikit_native.hid import FidoConnection, list_fido_devices
from _yubikit_native.sessions import WebAuthnClient

ORIGIN = "https://example.com"
RP_ID = "example.com"


def prompt_up() -> None:
    """Called when the authenticator is waiting for user presence."""
    print("\n👆 Touch your security key...")


def request_pin() -> str | None:
    """Called when a PIN is needed. Return the PIN or None to cancel."""
    try:
        pin = getpass.getpass("🔑 Enter PIN: ")
        return pin if pin else None
    except (EOFError, KeyboardInterrupt):
        return None


def request_uv() -> bool:
    """Called when biometric verification is available."""
    print("🔒 Biometric verification requested – proceeding")
    return True


def random_challenge() -> bytes:
    """Generate a random challenge (32 bytes)."""
    return os.urandom(32)


def b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main() -> None:
    # 1. Find a FIDO HID device
    devices = list_fido_devices()
    if not devices:
        print(
            "No FIDO HID devices found. Insert a security key and try again.",
            file=sys.stderr,
        )
        sys.exit(1)

    dev = devices[0]
    print(f"Using device: {dev.path} (PID=0x{dev.pid:04X})")

    # 2. Open connection and create WebAuthn client
    conn = FidoConnection(dev.path, dev.pid)
    client = WebAuthnClient(
        conn,
        origin=ORIGIN,
        prompt_up=prompt_up,
        request_pin=request_pin,
        request_uv=request_uv,
    )

    # 3. Registration ceremony
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

    # 4. Authentication ceremony
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
