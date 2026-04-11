"""
Demonstrates CTAP2 authenticatorSelection and authenticatorGetInfo using yubikit.

Opens CTAP2 sessions over both FIDO HID and SmartCard (CCID) transports,
calls selection() with auto-cancel, then prints authenticator info.

Usage: uv run python examples/ctap2_selection.py
"""

import threading

from _yubikit_native.hid import FidoConnection, list_fido_devices
from _yubikit_native.pcsc import PcscConnection, list_readers
from _yubikit_native.sessions import Ctap2FidoSession, Ctap2Session

CANCEL_TIMEOUT = 5  # seconds


def on_keepalive(status: int) -> None:
    print(f"  [keepalive] status=0x{status:02X}")


def run_demo(session: Ctap2Session | Ctap2FidoSession, transport: str) -> None:
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


def print_info(info: dict) -> None:
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


def is_yubico_reader(reader: str) -> bool:
    return "Yubico" in reader or "YubiKey" in reader


def main() -> None:
    found_any = False

    # Discover FIDO HID devices
    try:
        fido_devs = list_fido_devices()
    except OSError:
        fido_devs = []

    # Discover CCID readers (filter to Yubico)
    try:
        readers = [r for r in list_readers() if is_yubico_reader(r)]
    except OSError:
        readers = []

    if not fido_devs and not readers:
        print("No YubiKeys found.")
        return

    # FIDO HID
    for dev in fido_devs:
        found_any = True
        print(f"Found FIDO HID device: {dev.path} (PID=0x{dev.pid:04X})")

        try:
            conn = FidoConnection(dev.path, dev.pid)
        except OSError as e:
            print(f"  Failed to open: {e}")
            continue

        print(
            f"  Device version: {conn.device_version[0]}.{conn.device_version[1]}"
            f".{conn.device_version[2]}, capabilities: 0x{conn.capabilities:02X}"
        )

        try:
            session = Ctap2FidoSession(conn)
        except Exception as e:
            print(f"  Failed to open CTAP2 session: {e}")
            continue

        run_demo(session, "FIDO HID")

    # CCID / SmartCard
    for reader in readers:
        found_any = True
        print(f"Found CCID reader: {reader}")

        try:
            conn = PcscConnection(reader)
        except OSError as e:
            print(f"  Failed to connect: {e}")
            continue

        try:
            session = Ctap2Session(conn)
        except Exception as e:
            print(f"  FIDO not available: {e}")
            continue

        run_demo(session, f"CCID ({reader})")

    if not found_any:
        print("No YubiKeys found.")


if __name__ == "__main__":
    main()
