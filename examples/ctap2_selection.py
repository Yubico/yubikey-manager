"""
Demonstrates CTAP2 authenticatorSelection and authenticatorGetInfo using yubikit.

Opens a CTAP2 session (preferring FIDO HID, falling back to CCID),
calls selection() with auto-cancel, then prints authenticator info.

Usage: uv run python examples/ctap2_selection.py
"""

import threading

from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.ctap2 import Ctap2Session
from yubikit.device import list_all_devices

CANCEL_TIMEOUT = 5  # seconds


def on_keepalive(status: int) -> None:
    print(f"  [keepalive] status=0x{status:02X}")


def run_demo(session: Ctap2Session, transport: str) -> None:
    """Run selection + get_info on a CTAP2 session."""

    # --- selection ---
    print(f"  Starting selection over {transport}...")
    print(f"  Touch the YubiKey to confirm (auto-cancel in {CANCEL_TIMEOUT}s)")

    event = threading.Event()
    timer = threading.Timer(CANCEL_TIMEOUT, event.set)
    timer.start()

    try:
        session.selection(event=event, on_keepalive=on_keepalive)
        selection_ok = True
        print("  ✓ Selection succeeded (user touched the device)")
    except OSError as e:
        msg = str(e)
        if "KeepaliveCancel" in msg:
            print("  ✗ Selection was cancelled (timeout)")
            selection_ok = False
        elif "InvalidCommand" in msg:
            print("  ⚠ Selection not supported (CTAP 2.1+ required)")
            selection_ok = True  # still call get_info
        else:
            print(f"  ✗ Selection failed: {e}")
            selection_ok = False
    finally:
        event.set()
        timer.cancel()

    # --- get_info ---
    if selection_ok:
        print("  Calling get_info...")
        try:
            info = session.get_info()
            print_info(info)
        except Exception as e:
            print(f"  ✗ get_info failed: {e}")

    print()


def print_info(info: dict) -> None:  # type: ignore[type-arg]
    print("  Authenticator Info:")
    print(f"    Versions:    {info['versions']}")
    print(f"    AAGUID:      {info['aaguid'].hex()}")
    if info["extensions"]:
        print(f"    Extensions:  {info['extensions']}")
    if info["options"]:
        print(f"    Options:     {info['options']}")
    print(f"    Max msg:     {info['max_msg_size']} bytes")
    if info["pin_uv_protocols"]:
        print(f"    PIN/UV:      {info['pin_uv_protocols']}")
    if info["firmware_version"] is not None:
        print(f"    Firmware:    {info['firmware_version']}")
    if info["transports"]:
        print(f"    Transports:  {info['transports']}")
    if info["algorithms"]:
        algs = [a["alg"] for a in info["algorithms"]]
        print(f"    Algorithms:  {algs}")
    if info["remaining_disc_creds"] is not None:
        print(f"    Remaining discoverable credentials: {info['remaining_disc_creds']}")


def main() -> None:
    devices = list_all_devices()
    if not devices:
        print("No YubiKeys found.")
        return

    for dev, info in devices:
        print(f"Found YubiKey: {info.serial or 'Unknown serial'}")

        conn: FidoConnection | SmartCardConnection
        transport: str
        if dev.supports_connection(FidoConnection):  # type: ignore[arg-type]
            transport = "FIDO HID"
            try:
                conn = dev.open_connection(FidoConnection)  # type: ignore[arg-type]
            except OSError as e:
                print(f"  Failed to open: {e}")
                continue
        elif dev.supports_connection(SmartCardConnection):
            transport = "CCID"
            try:
                conn = dev.open_connection(SmartCardConnection)
            except OSError as e:
                print(f"  Failed to open: {e}")
                continue
        else:
            print("  No usable connection available.")
            continue

        try:
            session = Ctap2Session(conn)
        except Exception as e:
            print(f"  Failed to open CTAP2 session: {e}")
            continue

        run_demo(session, transport)


if __name__ == "__main__":
    main()
