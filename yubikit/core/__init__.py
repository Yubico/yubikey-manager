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

from enum import Enum, unique, auto
from typing import (
    Type,
    List,
    Dict,
    Tuple,
    TypeVar,
    Union,
    Optional,
    Hashable,
    NamedTuple,
)
import re
import abc


_VERSION_STRING_PATTERN = re.compile(r"\b(?P<major>\d+).(?P<minor>\d).(?P<patch>\d)\b")


class Version(NamedTuple):
    """3-digit version tuple."""

    major: int
    minor: int
    patch: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Version":
        return cls(*data)

    @classmethod
    def from_string(cls, data: str) -> "Version":
        m = _VERSION_STRING_PATTERN.search(data)
        if m:
            return cls(
                int(m.group("major")), int(m.group("minor")), int(m.group("patch"))
            )
        raise ValueError("No version found in string")


class TRANSPORT(Enum):
    """YubiKey physical connection transports."""

    USB = auto()
    NFC = auto()


@unique
class AID(bytes, Enum):
    """YubiKey Application smart card AID values."""

    OTP = bytes.fromhex("a0000005272001")
    MANAGEMENT = bytes.fromhex("a000000527471117")
    OPENPGP = bytes.fromhex("d27600012401")
    OATH = bytes.fromhex("a0000005272101")
    PIV = bytes.fromhex("a000000308")
    FIDO = bytes.fromhex("a0000006472f0001")
    HSMAUTH = bytes.fromhex("a000000527210701")


class Connection(abc.ABC):
    """A connection to a YubiKey"""

    def close(self) -> None:
        """Close the device, releasing any held resources."""

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()


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

    def supports_connection(self, connection_type: Type[T_Connection]) -> bool:
        """Check if a YubiKeyDevice supports a specific Connection type"""
        return False

    def open_connection(self, connection_type: Type[T_Connection]) -> T_Connection:
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


def require_version(
    my_version: Version, min_version: Tuple[int, int, int], message=None
):
    """Ensure a version is at least min_version."""
    # Skip version checks for major == 0, used for development builds.
    if my_version < min_version and my_version[0] != 0:
        if not message:
            message = "This action requires YubiKey %d.%d.%d or later" % min_version
        raise NotSupportedError(message)


def int2bytes(value: int, min_len: int = 0) -> bytes:
    buf = []
    while value > 0xFF:
        buf.append(value & 0xFF)
        value >>= 8
    buf.append(value)
    return bytes(reversed(buf)).rjust(min_len, b"\0")


def bytes2int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _tlv_parse(data):
    try:
        tag, rest = data[0], data[1:]
        if tag & 0x1F == 0x1F:  # Long form
            tag, rest = tag << 8 | rest[0], rest[1:]
            while tag & 0x80 == 0x80:  # Additional bytes
                tag, rest = tag << 8 | rest[0], rest[1:]

        ln, rest = rest[0], rest[1:]
        if ln == 0x80:
            raise ValueError("Indefinite length not supported")
        if ln > 0x80:
            n_bytes = ln - 0x80
            ln, rest = bytes2int(rest[:n_bytes]), rest[n_bytes:]

        value, rest = rest[:ln], rest[ln:]
    except IndexError:
        raise ValueError("Invalid encoding of tag/length")

    return tag, ln, value, rest


T_Tlv = TypeVar("T_Tlv", bound="Tlv")


class Tlv(bytes):
    @property
    def tag(self) -> int:
        return self._tag

    @property
    def length(self) -> int:
        return len(self) - self._value_offset

    @property
    def value(self) -> bytes:
        return self[self._value_offset :]

    def __new__(cls, tag_or_data: Union[int, bytes], value: Optional[bytes] = None):
        """This allows creation by passing either binary data, or tag and value."""
        if isinstance(tag_or_data, int):  # Tag and (optional) value
            tag = tag_or_data

            # Pack into Tlv
            buf = bytearray()
            buf.extend(int2bytes(tag))
            value = value or b""
            length = len(value)
            if length < 0x80:
                buf.append(length)
            else:
                ln_bytes = int2bytes(length)
                buf.append(0x80 | len(ln_bytes))
                buf.extend(ln_bytes)
            buf.extend(value)
            data = bytes(buf)
        else:  # Binary TLV data
            if value is not None:
                raise ValueError("value can only be provided if tag_or_data is a tag")
            data = tag_or_data

        # mypy thinks this is wrong
        return super(Tlv, cls).__new__(cls, data)  # type: ignore

    def __init__(self, tag_or_data: Union[int, bytes], value: Optional[bytes] = None):
        self._tag, ln, value, rest = _tlv_parse(self)
        if rest:
            raise ValueError("Incorrect TLV length")
        self._value_offset = len(self) - ln

    def __repr__(self):
        return f"Tlv(tag=0x{self.tag:02x}, value={self.value.hex()})"

    @classmethod
    def parse_from(cls: Type[T_Tlv], data: bytes) -> Tuple[T_Tlv, bytes]:
        tag, ln, value, rest = _tlv_parse(data)
        return cls(data[: len(data) - len(rest)]), rest

    @classmethod
    def parse_list(cls: Type[T_Tlv], data: bytes) -> List[T_Tlv]:
        res = []
        while data:
            tlv, data = cls.parse_from(data)
            res.append(tlv)
        return res

    @classmethod
    def parse_dict(cls: Type[T_Tlv], data: bytes) -> Dict[int, bytes]:
        return dict((tlv.tag, tlv.value) for tlv in cls.parse_list(data))

    @classmethod
    def unpack(cls: Type[T_Tlv], tag: int, data: bytes) -> bytes:
        tlv = cls(data)
        if tlv.tag != tag:
            raise ValueError(f"Wrong tag, got 0x{tlv.tag:02x} expected 0x{tag:02x}")
        return tlv.value
