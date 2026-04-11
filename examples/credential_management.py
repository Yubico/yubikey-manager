"""
List all discoverable credentials stored on a YubiKey.

Uses list_all_devices to find a connected YubiKey, opens a CTAP2 session
(preferring FIDO HID over CCID), obtains a PIN token with credential
management permissions, then enumerates all RPs and their credentials.

Usage: uv run python examples/credential_management.py
"""

import getpass
import hashlib

from ykman.device import list_all_devices
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.ctap2 import (
    PERMISSION_CREDENTIAL_MGMT,
    ClientPin,
    CredentialManagement,
    Ctap2Session,
)


def print_credential(cred: dict) -> None:
    user = cred.get(6, {})  # CredMgmtResult::User
    cred_id = cred.get(7, {})  # CredMgmtResult::CredentialId
    cred_protect = cred.get(10)  # CredMgmtResult::CredProtect

    user_id = user.get("id", b"")
    user_name = user.get("name", "(unknown)")
    display_name = user.get("displayName", "")
    cred_id_bytes = cred_id.get("id", b"") if isinstance(cred_id, dict) else b""

    print(f"      User:        {user_name}")
    if display_name:
        print(f"      Display:     {display_name}")
    print(f"      User ID:     {user_id.hex()}")
    print(f"      Credential:  {cred_id_bytes.hex()[:32]}...")
    if cred_protect is not None:
        print(f"      CredProtect: {cred_protect}")


def list_credentials(cred_mgmt: CredentialManagement) -> None:
    """Enumerate and print all stored credentials."""
    existing, remaining = cred_mgmt.get_metadata()
    print(f"\n  Credentials stored: {existing}")
    print(f"  Remaining capacity: {remaining}")

    if existing == 0:
        print("  No credentials to list.")
        return

    rps = cred_mgmt.enumerate_rps()
    print(f"  Relying Parties: {len(rps)}\n")

    for rp_entry in rps:
        rp = rp_entry.get(3, {})  # CredMgmtResult::Rp
        rp_id_hash = rp_entry.get(4, b"")  # CredMgmtResult::RpIdHash
        rp_id = rp.get("id", "(unknown)")

        print(f"    RP: {rp_id}")

        # If we didn't get the hash from the response, compute it
        if not rp_id_hash and isinstance(rp_id, str):
            rp_id_hash = hashlib.sha256(rp_id.encode()).digest()

        creds = cred_mgmt.enumerate_creds(rp_id_hash)
        print(f"    Credentials: {len(creds)}")

        for i, cred in enumerate(creds):
            print(f"    [{i + 1}]")
            print_credential(cred)
        print()


def main() -> None:
    devices = list_all_devices()
    if not devices:
        print("No YubiKeys found.")
        return

    dev, info = devices[0]
    print(f"Using: {info.serial or 'Unknown serial'}")

    pin = getpass.getpass("  Enter PIN: ")

    if dev.supports_connection(FidoConnection):  # type: ignore[arg-type]
        print("  Using FIDO HID transport")
        conn = dev.open_connection(FidoConnection)  # type: ignore[arg-type]
    elif dev.supports_connection(SmartCardConnection):
        print("  Using CCID transport")
        conn = dev.open_connection(SmartCardConnection)
    else:
        print("  No usable connection available on this device.")
        return

    session = Ctap2Session(conn)

    with ClientPin(session) as client_pin:
        pin_token = client_pin.get_pin_token(
            pin, permissions=PERMISSION_CREDENTIAL_MGMT
        )
        protocol = client_pin.protocol

    with CredentialManagement(session, protocol, pin_token) as cred_mgmt:
        list_credentials(cred_mgmt)


if __name__ == "__main__":
    main()
