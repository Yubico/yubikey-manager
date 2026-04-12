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

import abc
import logging
import warnings
from enum import Enum, IntEnum, unique

from _yubikit_native.core import SmartCardProtocol as _NativeSmartCardProtocol

from .. import (
    TRANSPORT,
    USB_INTERFACE,
    ApplicationNotAvailableError,
    BadResponseError,
    Closable,
    CommandError,
    Connection,
    NotSupportedError,
    Version,
)
from .scp import (  # noqa: F401 - re-exported
    Scp03KeyParams,
    Scp11KeyParams,
    ScpKeyParams,
)

logger = logging.getLogger(__name__)


class SmartCardConnection(Connection, metaclass=abc.ABCMeta):
    usb_interface = USB_INTERFACE.CCID

    @property
    @abc.abstractmethod
    def transport(self) -> TRANSPORT:
        """Get the transport type of the connection (USB or NFC)"""

    @abc.abstractmethod
    def send_and_receive(self, apdu: bytes) -> tuple[bytes, int]:
        """Sends a command APDU and returns the response"""


class ApduError(CommandError):
    """Thrown when an APDU response has the wrong SW code"""

    def __init__(self, data: bytes, sw: int):
        self.data = data
        self.sw = sw

    def __str__(self):
        try:
            name = SW(self.sw).name
            return f"APDU error: SW=0x{self.sw:04x} ({name})"
        except ValueError:
            return f"APDU error: SW=0x{self.sw:04x}"


@unique
class ApduFormat(str, Enum):
    """APDU encoding format"""

    SHORT = "short"
    EXTENDED = "extended"


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
    SECURE_DOMAIN = bytes.fromhex("a000000151000000")


@unique
class SW(IntEnum):
    NO_INPUT_DATA = 0x6285
    VERIFY_FAIL_NO_RETRY = 0x63C0
    MEMORY_FAILURE = 0x6581
    WRONG_LENGTH = 0x6700
    SECURITY_CONDITION_NOT_SATISFIED = 0x6982
    AUTH_METHOD_BLOCKED = 0x6983
    DATA_INVALID = 0x6984
    CONDITIONS_NOT_SATISFIED = 0x6985
    COMMAND_NOT_ALLOWED = 0x6986
    INCORRECT_PARAMETERS = 0x6A80
    FUNCTION_NOT_SUPPORTED = 0x6A81
    FILE_NOT_FOUND = 0x6A82
    RECORD_NOT_FOUND = 0x6A83
    NO_SPACE = 0x6A84
    REFERENCE_DATA_NOT_FOUND = 0x6A88
    APPLET_SELECT_FAILED = 0x6999
    WRONG_PARAMETERS_P1P2 = 0x6B00
    INVALID_INSTRUCTION = 0x6D00
    CLASS_NOT_SUPPORTED = 0x6E00
    COMMAND_ABORTED = 0x6F00
    OK = 0x9000


INS_SELECT = 0xA4
P1_SELECT = 0x04
P2_SELECT = 0x00

INS_SEND_REMAINING = 0xC0


class SmartCardProtocol(Closable):
    """Smart Card protocol backed by a native Rust implementation."""

    def __init__(
        self,
        smartcard_connection: SmartCardConnection,
        ins_send_remaining: int = INS_SEND_REMAINING,
    ):
        self.connection = smartcard_connection
        self._native = _NativeSmartCardProtocol(
            smartcard_connection, ins_send_remaining
        )

    def close(self) -> None:
        self._native.close()

    def enable_touch_workaround(self, version: Version) -> None:
        warnings.warn(
            "Deprecated: use SmartCardProtocol.configure(version) instead.",
            DeprecationWarning,
        )
        self.configure(version)

    def configure(self, version: Version, force_short: bool = False) -> None:
        """Configure the connection optimally for the given YubiKey version."""
        self._native.configure(tuple(version), force_short)

    def send_apdu(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b"",
        le: int = 0,
    ) -> bytes:
        """Send APDU message.

        :param cla: The instruction class.
        :param ins: The instruction code.
        :param p1: The instruction parameter.
        :param p2: The instruction parameter.
        :param data: The command data in bytes.
        :param le: The maximum number of bytes in the data
            field of the response.
        """
        return bytes(self._native.send_apdu(cla, ins, p1, p2, data, le))

    def select(self, aid: bytes) -> bytes:
        """Perform a SELECT instruction.

        :param aid: The YubiKey application AID value.
        """
        logger.debug(f"Selecting AID: {aid.hex()}")
        try:
            return bytes(self._native.select(aid))
        except ApplicationNotAvailableError:
            raise
        except ApduError as e:
            if e.sw in (
                SW.FILE_NOT_FOUND,
                SW.APPLET_SELECT_FAILED,
                SW.INVALID_INSTRUCTION,
                SW.WRONG_PARAMETERS_P1P2,
            ):
                raise ApplicationNotAvailableError()
            raise

    def init_scp(self, key_params: ScpKeyParams) -> None:
        """Initialize SCP03/SCP11 secure messaging."""
        try:
            self._native.init_scp(key_params)
            logger.info("SCP initialized")
        except ApduError as e:
            if e.sw == SW.CLASS_NOT_SUPPORTED:
                raise NotSupportedError(
                    "This YubiKey does not support secure messaging"
                )
            if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
                raise ValueError("Incorrect SCP parameters")
            raise
        except BadResponseError:
            raise ValueError("Incorrect SCP parameters")
