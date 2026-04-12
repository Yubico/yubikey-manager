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

"""
Device enumeration and native connection implementations for YubiKeys.
"""

from __future__ import annotations

import abc
import logging
from enum import Enum
from threading import Event
from typing import Callable, Hashable, Iterable, Iterator, Mapping, TypeAlias

from _yubikit_native.device import NativeYubiKeyDevice
from _yubikit_native.device import list_devices as _native_list_devices
from _yubikit_native.device import scan_devices as _native_scan_devices
from _yubikit_native.hid import FidoConnection as _NativeFidoHidConnection
from _yubikit_native.hid import OtpConnection as _NativeOtpConnectionImpl
from _yubikit_native.pcsc import PcscConnection
from _yubikit_native.pcsc import list_readers as _native_list_readers
from yubikit.core import PID, TRANSPORT, Connection, YubiKeyDevice
from yubikit.core.fido import FidoConnection, SmartCardCtapDevice
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.logging import LOG_LEVEL
from yubikit.management import DeviceInfo
from yubikit.support import read_info  # noqa: F401 - re-exported

logger = logging.getLogger(__name__)


# --- Connection implementations ---


class NativeFidoConnection(FidoConnection):
    """FIDO connection backed by the native Rust CTAP HID transport."""

    def __init__(self, path: str, pid: int):
        self._native = _NativeFidoHidConnection(path, pid)
        self._device_version = self._native.device_version
        self._capabilities = self._native.capabilities
        self._path = path

    @property
    def capabilities(self) -> int:
        return self._capabilities

    @property
    def device_version(self) -> tuple[int, int, int]:
        return self._device_version

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> bytes:
        return bytes(self._native.call(cmd, data))

    def close(self) -> None:
        self._native.close()

    @classmethod
    def list_devices(cls) -> Iterator[NativeFidoConnection]:
        from _yubikit_native.hid import list_fido_devices as _native_list_fido_devices

        for dev in _native_list_fido_devices():
            yield cls(dev.path, dev.pid)


class _NativeOtpConnection(OtpConnection):
    """OTP connection backed by the Rust HID implementation."""

    def __init__(self, path: str):
        self._path = path
        self._native = _NativeOtpConnectionImpl(path)

    def close(self) -> None:
        self._native.close()

    def receive(self) -> bytes:
        data = bytes(self._native.get_feature_report())
        logger.log(LOG_LEVEL.TRAFFIC, "RECV: %s", data.hex())
        return data

    def send(self, data: bytes) -> None:
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", data.hex())
        self._native.set_feature_report(data)


YK_READER_NAME = "yubico yubikey"


class ScardSmartCardConnection(SmartCardConnection):
    def __init__(self, reader_name):
        self._native = PcscConnection.open(reader_name)
        self._transport = (
            TRANSPORT.USB if self._native.transport == "usb" else TRANSPORT.NFC
        )

    @property
    def transport(self):
        return self._transport

    def close(self):
        self._native.disconnect()

    def send_and_receive(self, apdu):
        """Sends a command APDU and returns the response data and sw"""
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", apdu.hex())
        resp = self._native.transmit(apdu)
        data = resp[:-2]
        sw = resp[-2] << 8 | resp[-1]
        logger.log(LOG_LEVEL.TRAFFIC, "RECV: %s SW=%04x", data.hex(), sw)
        return bytes(data), sw


def list_readers():
    try:
        return _native_list_readers()
    except OSError:
        return []


# --- Device enumeration ---


class REINSERT_STATUS(Enum):
    REMOVE = 1
    REINSERT = 2


class CancelledException(Exception):
    """Raised when the caller cancels an operation."""


class YkmanDevice(YubiKeyDevice):
    """YubiKey device reference, with optional PID"""

    def __init__(self, transport: TRANSPORT, fingerprint: Hashable, pid: PID | None):
        super(YkmanDevice, self).__init__(transport, fingerprint)
        self._pid = pid

    @property
    def pid(self) -> PID | None:
        """Return the PID of the YubiKey, if available."""
        return self._pid

    def reinsert(
        self,
        reinsert_cb: Callable[[REINSERT_STATUS], None] | None = None,
        event: Event | None = None,
    ) -> None:
        """Wait for the user to remove and reinsert the YubiKey.

        This may be required to perform certain operations, such as FIDO reset.

        This method will attempt to verify that the same YubiKey is reinserted,
        but it will only fail when this is definitely not the case (eg. if the serial
        number does not match).

        :param reinsert_cb: Callback to indicate the the YubiKey has been removed,
        and should be reinserted.
        :param event: Optional event to cancel (throws CancelledException).
        """
        self._do_reinsert(reinsert_cb or (lambda _: None), event or Event())

    @abc.abstractmethod
    def _do_reinsert(
        self, reinsert_cb: Callable[[REINSERT_STATUS], None], event: Event
    ) -> None:
        pass

    def __repr__(self):
        return "%s(pid=%04x, fingerprint=%r)" % (
            type(self).__name__,
            self.pid or 0,
            self.fingerprint,
        )


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

    @property
    def reader_name(self) -> str | None:
        return self._native.reader_name

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
