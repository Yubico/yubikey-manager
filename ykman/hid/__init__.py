# Copyright (c) 2020 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import logging
from threading import Event
from typing import Callable

from _ykman_native.hid import HidConnection
from _ykman_native.hid import list_otp_devices as _native_list_otp

from yubikit.core.otp import OtpConnection
from yubikit.logging import LOG_LEVEL
from yubikit.support import read_info

from ..base import REINSERT_STATUS, CancelledException
from .base import OtpYubiKeyDevice
from .fido import list_ctap_devices

__all__ = [
    "list_otp_devices",
    "list_ctap_devices",
]
logger = logging.getLogger(__name__)


class NativeOtpConnection(OtpConnection):
    """OTP connection backed by the Rust HID implementation."""

    def __init__(self, path):
        self._conn = HidConnection(path)

    def close(self):
        self._conn.close()

    def receive(self):
        data = bytes(self._conn.get_feature_report())
        logger.log(LOG_LEVEL.TRAFFIC, "RECV: %s", data.hex())
        return data

    def send(self, data):
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", data.hex())
        self._conn.set_feature_report(data)


def _list_devices() -> list[OtpYubiKeyDevice]:
    devices = []
    for info in _native_list_otp():
        devices.append(OtpYubiKeyDevice(info.path, info.pid, NativeOtpConnection))
    return devices


list_otp_devices: Callable[[], list[OtpYubiKeyDevice]] = _list_devices


def _otp_reinsert(
    self: OtpYubiKeyDevice, reinsert_cb: Callable[[REINSERT_STATUS], None], event: Event
) -> None:
    removed_state = None
    with self.open_connection(OtpConnection) as conn:
        info = read_info(conn, self.pid)

    reinsert_cb(REINSERT_STATUS.REMOVE)
    logger.debug(f"Waiting for removal of device {self.path}")
    while not event.wait(0.5):
        keys = list_otp_devices()
        present = {k.path for k in keys}
        if removed_state is None:
            if self.path not in present:
                logger.debug(f"Removed! {self.path}")
                reinsert_cb(REINSERT_STATUS.REINSERT)
                removed_state = present
        else:
            added = present - removed_state
            if len(added) == 1:
                dev_fp = next(iter(added))  # Path may have changed
                logger.debug(f"Inserted! {dev_fp}")
                key = next(k for k in keys if k.path == dev_fp)
                # Update path
                self.path = key.path
                with self.open_connection(OtpConnection) as conn:
                    info2 = read_info(conn, self.pid)
                if info.serial != info2.serial or info.version != info2.version:
                    raise ValueError("Reinserted YubiKey does not match the original")
                return
            elif len(added) > 1:
                raise ValueError("Multiple YubiKeys inserted")

    raise CancelledException()


# Patch the reinsert method to the OtpYubiKeyDevice class for the correct backend
OtpYubiKeyDevice._do_reinsert = _otp_reinsert  # type: ignore
