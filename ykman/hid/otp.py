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
from time import sleep
from typing import Callable

from _ykman_native.hid import HidConnection
from _ykman_native.hid import list_otp_devices as _native_list_otp

from yubikit.core import PID, TRANSPORT, USB_INTERFACE
from yubikit.core.otp import CommandRejectedError, OtpConnection, OtpProtocol
from yubikit.logging import LOG_LEVEL
from yubikit.support import read_info

from ..base import REINSERT_STATUS, CancelledException, YkmanDevice

logger = logging.getLogger(__name__)


class _NativeOtpConnection(OtpConnection):
    """OTP connection backed by the Rust HID implementation."""

    def __init__(self, path: str):
        self._path = path
        self._conn = HidConnection(path)

    def close(self) -> None:
        self._conn.close()

    def receive(self) -> bytes:
        data = bytes(self._conn.get_feature_report())
        logger.log(LOG_LEVEL.TRAFFIC, "RECV: %s", data.hex())
        return data

    def send(self, data: bytes) -> None:
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", data.hex())
        self._conn.set_feature_report(data)


class OtpYubiKeyDevice(YkmanDevice):
    """YubiKey USB HID OTP device"""

    def __init__(self, path: str, pid: int):
        super().__init__(TRANSPORT.USB, path, PID(pid))
        self.path = path

    def supports_connection(self, connection_type):
        return issubclass(_NativeOtpConnection, connection_type)

    def open_connection(self, connection_type):
        assert isinstance(connection_type, type)  # noqa: S101
        if self.supports_connection(connection_type):
            conn = _NativeOtpConnection(self.path)
            # If OTP-only, then it can't be in reclaim
            if self.pid and self.pid.usb_interfaces != USB_INTERFACE.OTP:
                proto = OtpProtocol(conn)
                for _ in range(6):
                    try:
                        proto.send_and_receive(0x10, b"")
                        break
                    except CommandRejectedError:
                        sleep(0.5)
            return conn

        return super().open_connection(connection_type)

    def _do_reinsert(
        self, reinsert_cb: Callable[[REINSERT_STATUS], None], event: Event
    ) -> None:
        with self.open_connection(OtpConnection) as conn:
            info = read_info(conn, self.pid)

        reinsert_cb(REINSERT_STATUS.REMOVE)
        logger.debug(f"Waiting for removal of device {self.path}")
        removed_state = None
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
                    dev_fp = next(iter(added))
                    logger.debug(f"Inserted! {dev_fp}")
                    key = next(k for k in keys if k.path == dev_fp)
                    self.path = key.path
                    with self.open_connection(OtpConnection) as conn:
                        info2 = read_info(conn, self.pid)
                    if info.serial != info2.serial or info.version != info2.version:
                        raise ValueError(
                            "Reinserted YubiKey does not match the original"
                        )
                    return
                elif len(added) > 1:
                    raise ValueError("Multiple YubiKeys inserted")

        raise CancelledException()


def list_otp_devices() -> list[OtpYubiKeyDevice]:
    devices = []
    for info in _native_list_otp():
        devices.append(OtpYubiKeyDevice(info.path, info.pid))
    return devices
