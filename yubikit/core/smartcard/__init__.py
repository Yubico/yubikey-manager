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

from .. import (
    Version,
    TRANSPORT,
    USB_INTERFACE,
    Connection,
    NotSupportedError,
    ApplicationNotAvailableError,
    CommandError,
    BadResponseError,
)
from .scp import (
    ScpState,
    ScpKeyParams,
    Scp03KeyParams,
    Scp11KeyParams,
    INS_EXTERNAL_AUTHENTICATE,
)
from yubikit.logging import LOG_LEVEL
from enum import Enum, IntEnum, unique
from time import time
from typing import Tuple
import abc
import struct
import logging
import warnings


logger = logging.getLogger(__name__)


class SmartCardConnection(Connection, metaclass=abc.ABCMeta):
    usb_interface = USB_INTERFACE.CCID

    @property
    @abc.abstractmethod
    def transport(self) -> TRANSPORT:
        """Get the transport type of the connection (USB or NFC)"""

    @abc.abstractmethod
    def send_and_receive(self, apdu: bytes) -> Tuple[bytes, int]:
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


class ApduProcessor(abc.ABC):
    @abc.abstractmethod
    def send_apdu(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes,
        le: int,
    ) -> Tuple[bytes, int]: ...


class ApduFormatProcessor(ApduProcessor):
    def __init__(self, connection: SmartCardConnection):
        self.connection = connection

    def send_apdu(self, cla, ins, p1, p2, data, le):
        apdu = self.format_apdu(cla, ins, p1, p2, data, le)
        return self.connection.send_and_receive(apdu)

    @abc.abstractmethod
    def format_apdu(
        self, cla: int, ins: int, p1: int, p2: int, data: bytes, le: int
    ) -> bytes: ...


SHORT_APDU_MAX_CHUNK = 0xFF


class ShortApduProcessor(ApduFormatProcessor):
    def format_apdu(self, cla, ins, p1, p2, data, le):
        buf = struct.pack(">BBBB", cla, ins, p1, p2)
        if data:
            buf += struct.pack(">B", len(data)) + data
        if le:
            buf += struct.pack(">B", le)
        elif not data:
            # No data nor Le, need explicit Lc
            buf += b"\0"

        return buf

    def send_apdu(self, cla, ins, p1, p2, data, le):
        while len(data) > SHORT_APDU_MAX_CHUNK:
            chunk, data = (
                data[:SHORT_APDU_MAX_CHUNK],
                data[SHORT_APDU_MAX_CHUNK:],
            )
            apdu = self.format_apdu(0x10 | cla, ins, p1, p2, chunk, le)
            response, sw = self.connection.send_and_receive(apdu)
            if sw != SW.OK:
                return response, sw
        return super().send_apdu(cla, ins, p1, p2, data, le)


class ExtendedApduProcessor(ApduFormatProcessor):
    def __init__(self, connection, max_apdu_size):
        super().__init__(connection)
        self._max_apdu_size = max_apdu_size

    def format_apdu(self, cla, ins, p1, p2, data, le):
        buf = struct.pack(">BBBB", cla, ins, p1, p2)
        if data:
            buf += struct.pack(">BH", 0, len(data)) + data
        if le:
            if not data:
                # Use 3-byte Le
                buf += b"\0"
            buf += struct.pack(">H", le)

        if len(buf) > self._max_apdu_size:
            raise NotSupportedError("APDU length exceeds YubiKey capability")
        return buf


SW1_HAS_MORE_DATA = 0x61


class ChainedResponseProcessor(ApduProcessor):
    def __init__(
        self,
        connection: SmartCardConnection,
        extended_apdus: bool,
        max_apdu_size: int,
        ins_send_remaining: int = INS_SEND_REMAINING,
    ):
        self.connection = connection
        self.processor = (
            ExtendedApduProcessor(connection, max_apdu_size)
            if extended_apdus
            else ShortApduProcessor(connection)
        )
        self._get_data = self.processor.format_apdu(0, ins_send_remaining, 0, 0, b"", 0)

    def send_apdu(self, cla, ins, p1, p2, data, le):
        response, sw = self.processor.send_apdu(cla, ins, p1, p2, data, le)

        # Read chained response
        buf = b""
        while sw >> 8 == SW1_HAS_MORE_DATA:
            buf += response
            response, sw = self.connection.send_and_receive(self._get_data)

        buf += response
        return buf, sw


class TouchWorkaroundProcessor(ChainedResponseProcessor):
    def __init__(
        self,
        connection: SmartCardConnection,
        ins_send_remaining: int = INS_SEND_REMAINING,
    ):
        super().__init__(
            connection, True, _MaxApduSize.YK4, ins_send_remaining=ins_send_remaining
        )
        self._last_long_resp = 0.0

    def send_apdu(self, cla, ins, p1, p2, data, le):
        if self._last_long_resp > 0 and time() - self._last_long_resp < 2:
            logger.debug("Sending dummy APDU as touch workaround")
            # Dummy APDU, returns error
            super().send_apdu(0, 0, 0, 0, b"", 0)
            self._last_long_resp = 0

        resp, sw = super().send_apdu(cla, ins, p1, p2, data, le)

        if len(resp) > 54:
            self._last_long_resp = time()
        else:
            self._last_long_resp = 0

        return resp, sw


class ScpProcessor(ChainedResponseProcessor):
    def __init__(
        self,
        connection: SmartCardConnection,
        scp_state: ScpState,
        max_apdu_size: int,
        ins_send_remaining: int = INS_SEND_REMAINING,
    ):
        super().__init__(
            connection, True, max_apdu_size, ins_send_remaining=ins_send_remaining
        )
        self._state = scp_state

    def send_apdu(self, cla, ins, p1, p2, data, le, encrypt: bool = True):
        cla |= 0x04

        if encrypt:
            logger.log(LOG_LEVEL.TRAFFIC, "Plaintext data: %s", data.hex())
            data = self._state.encrypt(data)

        # Calculate and add MAC to data
        apdu = self.processor.format_apdu(cla, ins, p1, p2, data + b"\0" * 8, 0)
        mac = self._state.mac(apdu[:-8])
        data = data + mac

        resp, sw = super().send_apdu(cla, ins, p1, p2, data, le)

        # Un-MAC and decrypt, if needed
        if resp:
            resp = self._state.unmac(resp, sw)
            if resp:
                resp = self._state.decrypt(resp)
                logger.log(LOG_LEVEL.TRAFFIC, "Plaintext resp: %s", resp.hex())

        return resp, sw


class _MaxApduSize(IntEnum):
    NEO = 1390
    YK4 = 2038
    YK4_3 = 3062


class SmartCardProtocol:
    """An implementation of the Smart Card protocol."""

    def __init__(
        self,
        smartcard_connection: SmartCardConnection,
        ins_send_remaining: int = INS_SEND_REMAINING,
    ):
        self.connection = smartcard_connection
        self._max_apdu_size = _MaxApduSize.NEO
        self._apdu_format = ApduFormat.SHORT
        self._ins_send_remaining = ins_send_remaining
        self._reset_processor()

    def _reset_processor(self) -> None:
        self._processor = ChainedResponseProcessor(
            self.connection,
            self._apdu_format == ApduFormat.EXTENDED,
            self._max_apdu_size,
            self._ins_send_remaining,
        )

    @property
    def apdu_format(self) -> ApduFormat:
        warnings.warn(
            "Deprecated: do not read apdu_format.",
            DeprecationWarning,
        )

        return self._apdu_format

    @apdu_format.setter
    def apdu_format(self, value) -> None:
        if value == self._apdu_format:
            return
        if value != ApduFormat.EXTENDED:
            raise ValueError(f"Cannot change to {value}")
        self._apdu_format = value
        self._reset_processor()

    def close(self) -> None:
        self.connection.close()

    def enable_touch_workaround(self, version: Version) -> None:
        warnings.warn(
            "Deprecated: use SmartCardProtocol.configure(version) instead.",
            DeprecationWarning,
        )
        self._do_enable_touch_workaround(version)

    def _do_enable_touch_workaround(self, version: Version) -> bool:
        if self.connection.transport == TRANSPORT.USB and (
            (4, 2, 0) <= version <= (4, 2, 6)
        ):
            self._max_apdu_size = _MaxApduSize.YK4
            self._apdu_format = ApduFormat.EXTENDED
            self._processor = TouchWorkaroundProcessor(
                self.connection, self._ins_send_remaining
            )
            logger.debug("Touch workaround enabled")
            return True
        return False

    def configure(self, version: Version) -> None:
        """Configure the connection optimally for the given YubiKey version."""
        if isinstance(self._processor, ScpProcessor):
            return
        if self._do_enable_touch_workaround(version):
            return

        if version[0] > 3:
            self._apdu_format = ApduFormat.EXTENDED
            self._max_apdu_size = (
                _MaxApduSize.YK4_3 if version >= (4, 3) else _MaxApduSize.YK4
            )
            self._reset_processor()

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
        resp, sw = self._processor.send_apdu(cla, ins, p1, p2, data, le)

        if sw != SW.OK:
            raise ApduError(resp, sw)

        return resp

    def select(self, aid: bytes) -> bytes:
        """Perform a SELECT instruction.

        :param aid: The YubiKey application AID value.
        """
        logger.debug(f"Selecting AID: {aid.hex()}")
        self._reset_processor()

        try:
            return self.send_apdu(0, INS_SELECT, P1_SELECT, P2_SELECT, aid)
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
        try:
            if isinstance(key_params, Scp03KeyParams):
                self._scp03_init(key_params)
            elif isinstance(key_params, Scp11KeyParams):
                self._scp11_init(key_params)
            else:
                raise ValueError("Unsupported ScpKeyParams")
            self._apdu_format = ApduFormat.EXTENDED
            self._max_apdu_size = _MaxApduSize.YK4_3
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

    def _scp03_init(self, key_params: Scp03KeyParams) -> None:
        logger.debug("Initializing SCP03")
        scp, host_cryptogram = ScpState.scp03_init(self.send_apdu, key_params)
        processor = ScpProcessor(
            self.connection, scp, _MaxApduSize.YK4_3, self._ins_send_remaining
        )

        # Send EXTERNAL AUTHENTICATE
        # P1 = C-DECRYPTION, R-ENCRYPTION, C-MAC, and R-MAC
        processor.send_apdu(
            0x84, INS_EXTERNAL_AUTHENTICATE, 0x33, 0, host_cryptogram, 0, encrypt=False
        )
        self._processor = processor

    def _scp11_init(self, key_params: Scp11KeyParams) -> None:
        logger.debug("Initializing SCP11")
        scp = ScpState.scp11_init(self.send_apdu, key_params)
        self._processor = ScpProcessor(
            self.connection, scp, _MaxApduSize.YK4_3, self._ins_send_remaining
        )
