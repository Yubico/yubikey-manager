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
from threading import Event
from typing import Callable

from _yubikit_native.core import OtpProtocol as _NativeOtpProtocol
from _yubikit_native.core import (
    calculate_crc,  # noqa: F401 - re-exported
    check_crc,  # noqa: F401 - re-exported
    modhex_decode,  # noqa: F401 - re-exported
    modhex_encode,  # noqa: F401 - re-exported
)

from . import USB_INTERFACE, CommandError, Connection, Version

logger = logging.getLogger(__name__)


MODHEX_ALPHABET = "cbdefghijklnrtuv"


class CommandRejectedError(CommandError):
    """The issues command was rejected by the YubiKey"""


class OtpConnection(Connection, metaclass=abc.ABCMeta):
    usb_interface = USB_INTERFACE.OTP

    @abc.abstractmethod
    def receive(self) -> bytes:
        """Reads an 8 byte feature report"""

    @abc.abstractmethod
    def send(self, data: bytes) -> None:
        """Writes an 8 byte feature report"""


CRC_OK_RESIDUAL = 0xF0B8

STATUS_PROCESSING = 1
STATUS_UPNEEDED = 2


class OtpProtocol:
    """OTP protocol backed by a native Rust implementation."""

    def __init__(self, otp_connection: OtpConnection):
        self.connection = otp_connection
        self._native = _NativeOtpProtocol(otp_connection)
        self.version = Version(*self._native.version)

    def close(self) -> None:
        self.connection.close()

    def send_and_receive(
        self,
        slot: int,
        data: bytes | None = None,
        expected_len: int | None = None,
        event: Event | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> bytes | None:
        """Sends a command to the YubiKey, and reads the response.

        :param slot:  The slot to send to.
        :param data:  The data payload to send.
        :param expected_len: If >= 0, verify CRC and return exactly this many
            bytes. If -1, return raw data without CRC validation. If None, no
            data is expected (status-only).
        :param event: Optional Event for cancelling a command.
        :param on_keepalive: Optional callback for touch status.
        :return: Response data, or None for status-only responses.
        """
        result = self._native.send_and_receive(
            slot, data, expected_len, event, on_keepalive
        )
        return bytes(result) if result is not None else None

    def read_status(self) -> bytes:
        """Receive status bytes from YubiKey.

        :return: Status bytes (first 3 bytes are the firmware version).
        """
        return bytes(self._native.read_status())
