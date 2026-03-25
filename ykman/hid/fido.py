from __future__ import annotations

import logging
from threading import Event
from typing import Callable, Iterator

from _yubikit_native.hid import FidoConnection as _NativeFidoConnection
from _yubikit_native.hid import list_fido_devices as _native_list_fido_devices
from fido2.ctap import STATUS, CtapDevice

from yubikit.core import PID, TRANSPORT, USB_INTERFACE, Connection
from yubikit.support import read_info

from ..base import REINSERT_STATUS, CancelledException, YkmanDevice
from ..fido import FidoConnection

logger = logging.getLogger(__name__)


class NativeFidoConnection(CtapDevice, Connection):
    """FIDO connection backed by the native Rust CTAP HID transport."""

    usb_interface = USB_INTERFACE.FIDO

    def __init__(self, path: str, pid: PID):
        self._native = _NativeFidoConnection(path, pid)
        self._device_version = self._native.device_version
        self._capabilities = self._native.capabilities
        self._path = path

    @property
    def capabilities(self) -> int:
        return self._capabilities

    @property
    def device_version(self) -> tuple[int, int, int]:
        return self._device_version

    @property
    def version(self) -> int:
        return 2  # CTAP HID protocol version

    @property
    def product_name(self) -> str | None:
        return None

    @property
    def serial_number(self) -> str | None:
        return None

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        return bytes(self._native.call(cmd, data))

    def close(self) -> None:
        self._native.close()

    @classmethod
    def list_devices(cls) -> Iterator[NativeFidoConnection]:
        for dev in _native_list_fido_devices():
            yield cls(dev.path, dev.pid)


class CtapYubiKeyDevice(YkmanDevice):
    """YubiKey FIDO USB HID device"""

    def __init__(self, path: str, pid: PID):
        super().__init__(TRANSPORT.USB, path, pid)
        self._path = path

    def supports_connection(self, connection_type):
        return issubclass(NativeFidoConnection, connection_type)

    def open_connection(self, connection_type):
        assert isinstance(connection_type, type)  # noqa: S101
        if self.supports_connection(connection_type):
            assert self.pid is not None  # noqa: S101
            return NativeFidoConnection(
                str(self._path),
                self.pid,
            )
        return super().open_connection(connection_type)

    def _do_reinsert(self, reinsert_cb, event):
        removed_state = None
        with self.open_connection(FidoConnection) as conn:
            assert isinstance(conn, Connection)  # noqa: S101
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
                    self.descriptor = key.descriptor  # type: ignore[has-type]
                    with self.open_connection(FidoConnection) as conn:
                        assert isinstance(conn, Connection)  # noqa: S101
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
    for dev in _native_list_fido_devices():
        try:
            devs.append(CtapYubiKeyDevice(dev.path, dev.pid))
        except ValueError:
            logger.debug(f"Unsupported Yubico device with PID: {dev.pid:02x}")
    return devs
