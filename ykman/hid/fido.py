from __future__ import annotations

import logging
from threading import Event
from typing import Callable, Iterator

from fido2.ctap import STATUS, CtapDevice

from _yubikit_native.hid import FidoConnection as _NativeFidoConnection
from _yubikit_native.hid import list_fido_devices as _native_list_fido_devices
from yubikit.core import USB_INTERFACE, Connection

from ..fido import FidoConnection  # noqa: F401

logger = logging.getLogger(__name__)


class NativeFidoConnection(CtapDevice, Connection):
    """FIDO connection backed by the native Rust CTAP HID transport."""

    usb_interface = USB_INTERFACE.FIDO

    def __init__(self, path: str, pid: int):
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
