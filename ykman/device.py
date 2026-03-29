# Copyright (c) 2015-2020 Yubico AB
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
from typing import Callable, Iterable, Mapping, TypeAlias

from _yubikit_native.device import NativeYubiKeyDevice
from _yubikit_native.device import list_devices as _native_list_devices
from _yubikit_native.device import scan_devices as _native_scan_devices
from yubikit.core import PID, TRANSPORT, Connection
from yubikit.core.fido import FidoConnection, SmartCardCtapDevice
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import (
    DeviceInfo,
)
from yubikit.support import read_info  # noqa: F401 - re-exported

from .base import REINSERT_STATUS, CancelledException, YkmanDevice
from .hid.fido import NativeFidoConnection
from .hid.otp import _NativeOtpConnection
from .pcsc import ScardSmartCardConnection

logger = logging.getLogger(__name__)


_T_CONNECTION: TypeAlias = type[Connection] | type[FidoConnection]

# Map connection types to native transport names for list_devices
_CONNECTION_TRANSPORT_MAP: dict[_T_CONNECTION, str] = {
    SmartCardConnection: "ccid",
    OtpConnection: "otp",
    FidoConnection: "fido",
}

_DEFAULT_CONNECTION_TYPES: list[_T_CONNECTION] = list(_CONNECTION_TRANSPORT_MAP.keys())


def scan_devices() -> tuple[Mapping[PID, int], int]:
    """Scan USB for attached YubiKeys, without opening any connections.

    The native implementation handles Windows non-admin FIDO fallback.

    :return: A dict mapping PID to device count, and a state object which can be
        used to detect changes in attached devices.
    """
    raw_counts, state = _native_scan_devices()

    # Convert raw PID ints to PID enum values
    merged: dict[PID, int] = {}
    for pid_int, count in raw_counts.items():
        try:
            merged[PID(pid_int)] = count
        except ValueError:
            logger.debug(f"Unsupported PID: {pid_int:#04x}")

    return merged, state


class _NativeCompositeDevice(YkmanDevice):
    """YubiKey device backed by native Rust enumeration."""

    def __init__(self, native_dev: NativeYubiKeyDevice, info: DeviceInfo):
        pid = PID(native_dev.pid) if native_dev.pid else None
        fingerprint = (
            native_dev.reader_name or native_dev.hid_path or native_dev.fido_path or ""
        )
        transport = TRANSPORT.NFC if native_dev.transport == "nfc" else TRANSPORT.USB
        super().__init__(transport, fingerprint, pid)
        self._native = native_dev
        self._info = info

    def supports_connection(self, connection_type: type) -> bool:
        if issubclass(connection_type, SmartCardConnection):
            return self._native.reader_name is not None
        if issubclass(connection_type, OtpConnection):
            return self._native.hid_path is not None
        if issubclass(connection_type, FidoConnection):
            return self._native.fido_path is not None
        return False

    def open_connection(self, connection_type):  # type: ignore[override]
        assert isinstance(connection_type, type)  # noqa: S101
        if issubclass(connection_type, SmartCardConnection):
            reader = self._native.reader_name
            if reader is not None:
                return ScardSmartCardConnection(reader)
        if issubclass(connection_type, FidoConnection):
            fido_path = self._native.fido_path
            if fido_path is not None and self.pid is not None:
                if issubclass(connection_type, SmartCardCtapDevice):
                    reader = self._native.reader_name
                    if reader is not None:
                        return SmartCardCtapDevice(ScardSmartCardConnection(reader))
                return NativeFidoConnection(fido_path, self.pid)
        if issubclass(connection_type, OtpConnection):
            hid_path = self._native.hid_path
            if hid_path is not None:
                return _NativeOtpConnection(hid_path)
        raise ValueError(f"Unsupported connection type: {connection_type}")

    def _do_reinsert(
        self, reinsert_cb: Callable[[REINSERT_STATUS], None], event: Event
    ) -> None:
        status_map = {
            "remove": REINSERT_STATUS.REMOVE,
            "reinsert": REINSERT_STATUS.REINSERT,
            "remove_from_reader": REINSERT_STATUS.REMOVE_FROM_READER,
            "place_on_reader": REINSERT_STATUS.PLACE_ON_READER,
        }
        try:
            self._native.reinsert(
                lambda s: reinsert_cb(status_map[s]),
                lambda: event.is_set(),
            )
        except RuntimeError as e:
            msg = str(e)
            if "cancelled" in msg.lower():
                raise CancelledException() from e
            if "different" in msg.lower():
                raise ValueError(msg) from e
            raise


def _device_info_from_native_dev(native_dev: NativeYubiKeyDevice) -> DeviceInfo:
    """Convert a NativeYubiKeyDevice's info dict to a DeviceInfo."""
    from yubikit.management import _device_info_from_native

    return _device_info_from_native(native_dev.info())


def list_all_devices(
    connection_types: Iterable[_T_CONNECTION] = _DEFAULT_CONNECTION_TYPES,
) -> list[tuple[YkmanDevice, DeviceInfo]]:
    """Connect to all attached YubiKeys and read device info from them.

    :param connection_types: An iterable of YubiKey connection types.
    :return: A list of (device, info) tuples for each connected device.
    """
    transports = [
        _CONNECTION_TRANSPORT_MAP[ct]
        for ct in connection_types
        if ct in _CONNECTION_TRANSPORT_MAP
    ]
    if not transports:
        return []

    results: list[tuple[YkmanDevice, DeviceInfo]] = []
    for native_dev in _native_list_devices(transports):
        info = _device_info_from_native_dev(native_dev)
        results.append((_NativeCompositeDevice(native_dev, info), info))
    return results
