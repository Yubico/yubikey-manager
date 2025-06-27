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
import sys
from threading import Event
from typing import Callable

from yubikit.core import TRANSPORT
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.support import read_info

from ..base import PID, REINSERT_STATUS, CancelledException, YkmanDevice
from .base import OtpYubiKeyDevice

logger = logging.getLogger(__name__)


if sys.platform.startswith("linux"):
    from . import linux as backend
elif sys.platform.startswith("win32"):
    from . import windows as backend
elif sys.platform.startswith("darwin"):
    from . import macos as backend
elif sys.platform.startswith("freebsd"):
    from . import freebsd as backend
else:

    class backend:
        @staticmethod
        def list_devices():
            raise NotImplementedError(
                "OTP HID support is not implemented on this platform"
            )


list_otp_devices: Callable[[], list[OtpYubiKeyDevice]] = backend.list_devices


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


# Patch the reinsert method to the OtpYubiKeyDevice class so that it uses the correct backend
OtpYubiKeyDevice._do_reinsert = _otp_reinsert  # type: ignore


try:
    from fido2.hid import CtapHidDevice, list_descriptors, open_connection

    class CtapYubiKeyDevice(YkmanDevice):
        """YubiKey FIDO USB HID device"""

        def __init__(self, descriptor):
            super().__init__(TRANSPORT.USB, descriptor.path, PID(descriptor.pid))
            self.descriptor = descriptor

        def supports_connection(self, connection_type):
            return issubclass(CtapHidDevice, connection_type)

        def open_connection(self, connection_type):
            if self.supports_connection(connection_type):
                return CtapHidDevice(self.descriptor, open_connection(self.descriptor))
            return super().open_connection(connection_type)

        def _do_reinsert(self, reinsert_cb, event):
            removed_state = None
            with self.open_connection(FidoConnection) as conn:
                info = read_info(conn, self.pid)

            reinsert_cb(REINSERT_STATUS.REMOVE)
            logger.debug(f"Waiting for removal of device {self.fingerprint}")
            while not event.wait(0.5):
                keys = list_ctap_devices()
                present = {k.fingerprint for k in keys}
                if removed_state is None:
                    if self.fingerprint not in present:
                        logger.debug(f"Removed! {self.fingerprint}")
                        reinsert_cb(REINSERT_STATUS.REINSERT)
                        removed_state = present
                else:
                    added = present - removed_state
                    if len(added) == 1:
                        dev_fp = next(iter(added))  # Path may have changed
                        logger.debug(f"Inserted! {dev_fp}")
                        key = next(k for k in keys if k.fingerprint == dev_fp)
                        # Update fingerprint and descriptor
                        self._fingerprint = key.fingerprint
                        self.descriptor = key.descriptor
                        with self.open_connection(FidoConnection) as conn:
                            info2 = read_info(conn, self.pid)
                        if info.serial != info2.serial or info.version != info2.version:
                            raise ValueError(
                                "Reinserted YubiKey does not match the original"
                            )
                        return
                    elif len(added) > 1:
                        raise ValueError("Multiple YubiKeys inserted")

            raise CancelledException()

    def list_ctap_devices() -> list[CtapYubiKeyDevice]:
        devs = []
        for desc in list_descriptors():
            if desc.vid == 0x1050:
                try:
                    devs.append(CtapYubiKeyDevice(desc))
                except ValueError:
                    logger.debug(f"Unsupported Yubico device with PID: {desc.pid:02x}")
        return devs

except Exception:
    # CTAP not supported on this platform

    class CtapYubiKeyDevice(YkmanDevice):  # type: ignore
        def __init__(self, *args, **kwargs):
            raise NotImplementedError(
                "CTAP HID support is not implemented on this platform"
            )

        def _do_reinsert(self, *args, **kwargs):
            raise NotImplementedError(
                "CTAP HID support is not implemented on this platform"
            )

    def list_ctap_devices() -> list[CtapYubiKeyDevice]:
        raise NotImplementedError(
            "CTAP HID support is not implemented on this platform"
        )
