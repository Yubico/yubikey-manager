from __future__ import annotations

import logging
from threading import Event
from typing import Callable, Iterator

from _yubikit_native.hid import FidoConnection as _NativeFidoConnection
from _yubikit_native.hid import list_fido_devices as _native_list_fido_devices
from yubikit.core.fido import FidoConnection  # noqa: F401

logger = logging.getLogger(__name__)


class NativeFidoConnection(FidoConnection):
    """FIDO connection backed by the native Rust CTAP HID transport."""

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
        for dev in _native_list_fido_devices():
            yield cls(dev.path, dev.pid)
