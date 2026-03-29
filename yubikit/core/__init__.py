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

from __future__ import annotations

import abc
import logging
import re
from contextlib import contextmanager
from enum import Enum, IntEnum, IntFlag, unique
from threading import Timer
from typing import (
    Callable,
    ClassVar,
    Hashable,
    NamedTuple,
    TypeVar,
)

from _yubikit_native.core import (  # noqa: F401
    bytes2int,
    int2bytes,
)
from _yubikit_native.core import (
    oid_from_string as _oid_from_string,
)
from _yubikit_native.core import (
    oid_to_string as _oid_to_string,
)
from _yubikit_native.core import (
    tlv_encode as _tlv_encode,
)
from _yubikit_native.core import (
    tlv_parse as _tlv_parse,
)

logger = logging.getLogger(__name__)


_VERSION_STRING_PATTERN = re.compile(r"\b(?P<major>\d+).(?P<minor>\d).(?P<patch>\d)\b")


class Version(NamedTuple):
    """3-digit version tuple."""

    major: int
    minor: int
    patch: int

    def __str__(self):
        return "%d.%d.%d" % self

    def __bool__(self):
        return any(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> Version:
        return cls(*data)

    @classmethod
    def from_string(cls, data: str) -> Version:
        m = _VERSION_STRING_PATTERN.search(data)
        if m:
            return cls(
                int(m.group("major")), int(m.group("minor")), int(m.group("patch"))
            )
        raise ValueError("No version found in string")


@unique
class TRANSPORT(str, Enum):
    """YubiKey physical connection transports."""

    USB = "usb"
    NFC = "nfc"

    def __str__(self):
        return super().__str__().upper()


@unique
class USB_INTERFACE(IntFlag):
    """YubiKey USB interface identifiers."""

    OTP = 0x01
    FIDO = 0x02
    CCID = 0x04


@unique
class YUBIKEY(Enum):
    """YubiKey hardware platforms."""

    YKS = "YubiKey Standard"
    NEO = "YubiKey NEO"
    SKY = "Security Key by Yubico"
    YKP = "YubiKey Plus"
    YK4 = "YubiKey"  # This includes YubiKey 5


class Connection(abc.ABC):
    """A connection to a YubiKey"""

    usb_interface: ClassVar[USB_INTERFACE] = USB_INTERFACE(0)

    def close(self) -> None:
        """Close the device, releasing any held resources."""

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()


@unique
class PID(IntEnum):
    """USB Product ID values for YubiKey devices."""

    YKS_OTP = 0x0010
    NEO_OTP = 0x0110
    NEO_OTP_CCID = 0x0111
    NEO_CCID = 0x0112
    NEO_FIDO = 0x0113
    NEO_OTP_FIDO = 0x0114
    NEO_FIDO_CCID = 0x0115
    NEO_OTP_FIDO_CCID = 0x0116
    SKY_FIDO = 0x0120
    YK4_OTP = 0x0401
    YK4_FIDO = 0x0402
    YK4_OTP_FIDO = 0x0403
    YK4_CCID = 0x0404
    YK4_OTP_CCID = 0x0405
    YK4_FIDO_CCID = 0x0406
    YK4_OTP_FIDO_CCID = 0x0407
    YKP_OTP_FIDO = 0x0410

    @property
    def yubikey_type(self) -> YUBIKEY:
        return YUBIKEY[self.name.split("_", 1)[0]]

    @property
    def usb_interfaces(self) -> USB_INTERFACE:
        return USB_INTERFACE(sum(USB_INTERFACE[x] for x in self.name.split("_")[1:]))

    @classmethod
    def of(cls, key_type: YUBIKEY, interfaces: USB_INTERFACE) -> PID:
        suffix = "_".join(t.name or str(t) for t in USB_INTERFACE if t in interfaces)
        return cls[key_type.name + "_" + suffix]

    def supports_connection(self, connection_type: type[Connection]) -> bool:
        return connection_type.usb_interface in self.usb_interfaces


T_Connection = TypeVar("T_Connection", bound=Connection)


class YubiKeyDevice(abc.ABC):
    """YubiKey device reference"""

    def __init__(self, transport: TRANSPORT, fingerprint: Hashable):
        self._transport = transport
        self._fingerprint = fingerprint

    @property
    def transport(self) -> TRANSPORT:
        """Get the transport used to communicate with this YubiKey"""
        return self._transport

    def supports_connection(self, connection_type: type[Connection]) -> bool:
        """Check if a YubiKeyDevice supports a specific Connection type"""
        return False

    # mypy will not accept abstract types in type[T_Connection]
    def open_connection(
        self, connection_type: type[T_Connection] | Callable[..., T_Connection]
    ) -> T_Connection:
        """Opens a connection to the YubiKey"""
        raise ValueError("Unsupported Connection type")

    @property
    def fingerprint(self) -> Hashable:
        """Used to identify that device references from different enumerations represent
        the same physical YubiKey. This fingerprint is not stable between sessions, or
        after un-plugging, and re-plugging a device."""
        return self._fingerprint

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.fingerprint == other.fingerprint

    def __hash__(self):
        return hash(self.fingerprint)

    def __repr__(self):
        return f"{type(self).__name__}(fingerprint={self.fingerprint!r})"


class CommandError(Exception):
    """An error response from a YubiKey"""


class BadResponseError(CommandError):
    """Invalid response data from the YubiKey"""


class TimeoutError(CommandError):
    """An operation timed out waiting for something"""


class ApplicationNotAvailableError(CommandError):
    """The application is either disabled or not supported on this YubiKey"""


class NotSupportedError(ValueError):
    """Attempting an action that is not supported on this YubiKey"""


class InvalidPinError(CommandError, ValueError):
    """An incorrect PIN/PUK was used, with the number of attempts now remaining.

    WARNING: This exception currently inherits from ValueError for
    backwards-compatibility reasons. This will no longer be the case with the next major
    version of the library.
    """

    def __init__(self, attempts_remaining: int, message: str | None = None):
        super().__init__(message or f"Invalid PIN/PUK, {attempts_remaining} remaining")
        self.attempts_remaining = attempts_remaining


def _override_version(value: Version) -> None:
    """Override the version check for development devices."""
    logger.info(f"Overriding version check for development devices with {value}")
    from _yubikit_native.core import set_override_version

    set_override_version(*value)


def require_version(
    my_version: Version, min_version: tuple[int, int, int], message=None
):
    """Ensure a version is at least min_version."""
    if not my_version >= min_version:
        if not message:
            message = "This action requires YubiKey %d.%d.%d or later" % min_version
        raise NotSupportedError(message)


class Tlv(bytes):
    @property
    def tag(self) -> int:
        return self._tag

    @property
    def length(self) -> int:
        return self._value_ln

    @property
    def value(self) -> bytes:
        return self[self._value_offset : self._value_offset + self._value_ln]

    def __new__(cls, tag_or_data: int | bytes, value: bytes | None = None):
        """This allows creation by passing either binary data, or tag and value."""
        if isinstance(tag_or_data, int):  # Tag and (optional) value
            data = bytes(_tlv_encode(tag_or_data, value or b""))
        else:  # Binary TLV data
            if value is not None:
                raise ValueError("value can only be provided if tag_or_data is a tag")
            data = tag_or_data

        return super(Tlv, cls).__new__(cls, data)

    def __init__(self, tag_or_data: int | bytes, value: bytes | None = None):
        self._tag, self._value_offset, self._value_ln, end = _tlv_parse(self)
        if len(self) != end:
            raise ValueError("Incorrect TLV length")

    def __repr__(self):
        return f"Tlv(tag=0x{self.tag:02x}, value={self.value.hex()})"

    @classmethod
    def parse_from(cls: type[Tlv], data: bytes) -> tuple[Tlv, bytes]:
        tag, offs, ln, end = _tlv_parse(data)
        return cls(data[:end]), data[end:]

    @classmethod
    def parse_list(cls: type[Tlv], data: bytes) -> list[Tlv]:
        res = []
        while data:
            tlv, data = cls.parse_from(data)
            res.append(tlv)
        return res

    @classmethod
    def parse_dict(cls: type[Tlv], data: bytes) -> dict[int, bytes]:
        return dict((tlv.tag, tlv.value) for tlv in cls.parse_list(data))

    @classmethod
    def unpack(cls: type[Tlv], tag: int, data: bytes) -> bytes:
        tlv = cls(data)
        if tlv.tag != tag:
            raise ValueError(f"Wrong tag, got 0x{tlv.tag:02x} expected 0x{tag:02x}")
        return tlv.value


class Oid(bytes):
    @property
    def dotted_string(self) -> str:
        return _oid_to_string(self)

    @classmethod
    def from_string(cls, data: str) -> Oid:
        return cls(_oid_from_string(data))

    def __repr__(self) -> str:
        return f"Oid({self.dotted_string})"

    def __str__(self) -> str:
        return self.dotted_string


@contextmanager
def _timeout(f, timeout):
    timer = Timer(timeout, f)
    try:
        timer.start()
        yield None
    finally:
        timer.cancel()
