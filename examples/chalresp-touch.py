"""
Demonstrates challenge-response (HMAC-SHA1) with touch and cancel support.

Opens an OTP connection to a YubiKey, starts a challenge-response operation,
and cancels it after 5 seconds using a threading Event.

The on_keepalive callback prints the keepalive status as it waits for touch.

Usage: chalresp-touch.py
"""

import threading

from ykman import scripting as s
from yubikit.yubiotp import SLOT, YubiOtpSession

device = s.single()

session = YubiOtpSession(device.otp())
print(f"YubiKey version: {session.version}")

event = threading.Event()


def on_keepalive(status: int) -> None:
    if status == 2:  # STATUS_UPNEEDED
        print("Touch your YubiKey...")
    else:
        print(f"Keepalive status: {status}")


def cancel_after_delay() -> None:
    event.wait(5)
    if not event.is_set():
        print("Cancelling...")
        event.set()


cancel_thread = threading.Thread(target=cancel_after_delay, daemon=True)
cancel_thread.start()

challenge = b"\x00" * 8

try:
    result = session.calculate_hmac_sha1(
        SLOT.TWO, challenge, event=event, on_keepalive=on_keepalive
    )
    print(f"Response: {result.hex()}")
except Exception as e:
    print(f"Error: {e}")
