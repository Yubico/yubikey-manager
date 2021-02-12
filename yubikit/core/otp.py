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

from . import Connection, CommandError, TimeoutError, Version

from time import sleep
from threading import Event
from typing import Optional, Callable
import abc
import struct
import logging

logger = logging.getLogger(__name__)


class CommandRejectedError(CommandError):
    """The issues command was rejected by the YubiKey"""


class OtpConnection(Connection, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def receive(self) -> bytes:
        """Reads an 8 byte feature report"""

    @abc.abstractmethod
    def send(self, data: bytes) -> None:
        """Writes an 8 byte feature report"""


CRC_OK_RESIDUAL = 0xF0B8


def calculate_crc(data: bytes) -> int:
    crc = 0xFFFF
    for index in range(len(data)):
        crc ^= data[index]
        for i in range(8):
            j = crc & 1
            crc >>= 1
            if j == 1:
                crc ^= 0x8408
    return crc & 0xFFFF


def check_crc(data: bytes) -> bool:
    return calculate_crc(data) == CRC_OK_RESIDUAL


_MODHEX = "cbdefghijklnrtuv"


def modhex_encode(data: bytes) -> str:
    """Encode a bytes-like object using Modhex (modified hexadecimal) encoding."""
    return "".join(_MODHEX[b >> 4] + _MODHEX[b & 0xF] for b in data)


def modhex_decode(string: str) -> bytes:
    """Decode the Modhex (modified hexadecimal) string."""
    return bytes(
        _MODHEX.index(string[i]) << 4 | _MODHEX.index(string[i + 1])
        for i in range(0, len(string), 2)
    )


FEATURE_RPT_SIZE = 8
FEATURE_RPT_DATA_SIZE = FEATURE_RPT_SIZE - 1

SLOT_DATA_SIZE = 64
FRAME_SIZE = SLOT_DATA_SIZE + 6

RESP_PENDING_FLAG = 0x40  # Response pending flag
SLOT_WRITE_FLAG = 0x80  # Write flag - set by app - cleared by device
RESP_TIMEOUT_WAIT_FLAG = 0x20  # Waiting for timeout operation
DUMMY_REPORT_WRITE = 0x8F  # Write a dummy report to force update or abort

SEQUENCE_MASK = 0x1F

STATUS_OFFSET_PROG_SEQ = 0x4
STATUS_OFFSET_TOUCH_LOW = 0x5
CONFIG_STATUS_MASK = 0x1F

STATUS_PROCESSING = 1
STATUS_UPNEEDED = 2


def _should_send(packet, seq):
    """All-zero packets are skipped, except for the very first and last packets"""
    return seq in (0, 9) or any(packet)


def _format_frame(slot, payload):
    return payload + struct.pack("<BH", slot, calculate_crc(payload)) + b"\0\0\0"


class OtpProtocol:
    def __init__(self, otp_connection: OtpConnection):
        self.connection = otp_connection
        report = self._receive()
        self.version = Version.from_bytes(report[1:4])
        if self.version[0] == 3:  # NEO, may have cached pgmSeq in arbitrator
            try:  # Force communication with applet to refresh pgmSeq
                # Write an invalid scan map, does nothing
                self.send_and_receive(0x12, b"c" * 51)
            except CommandRejectedError:
                pass  # This is expected

    def close(self) -> None:
        self.connection.close()

    def send_and_receive(
        self,
        slot: int,
        data: Optional[bytes] = None,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ) -> bytes:
        """Sends a command to the YubiKey, and reads the response.

        If the command results in a configuration update, the programming sequence
        number is verified and the updated status bytes are returned.

        @param slot  the slot to send to
        @param data  the data payload to send
        @param state optional CommandState for listening for user presence requirement
            and for cancelling a command.
        @return response data (including CRC) in the case of data, or an updated status
            struct
        """
        payload = (data or b"").ljust(SLOT_DATA_SIZE, b"\0")
        if len(payload) > SLOT_DATA_SIZE:
            raise ValueError("Payload too large for HID frame")
        if not on_keepalive:
            on_keepalive = lambda x: None  # noqa
        frame = _format_frame(slot, payload)

        logger.debug("SEND: %s", frame.hex())
        response = self._read_frame(
            self._send_frame(frame), event or Event(), on_keepalive
        )
        logger.debug("RECV: %s", response.hex())
        return response

    def _receive(self):
        report = self.connection.receive()
        if len(report) != FEATURE_RPT_SIZE:
            raise Exception(
                "Incorrect reature report size (was %d, expected %d)"
                % len(report, FEATURE_RPT_SIZE)
            )
        return report

    def read_status(self) -> bytes:
        """Receive status bytes from YubiKey

        @return status bytes (first 3 bytes are the firmware version)
        @throws IOException in case of communication error
        """
        return self._receive()[1:-1]

    def _await_ready_to_write(self):
        """Sleep for up to ~1s waiting for the WRITE flag to be unset"""
        for _ in range(20):
            if (self._receive()[FEATURE_RPT_DATA_SIZE] & SLOT_WRITE_FLAG) == 0:
                return
            sleep(0.05)
        raise Exception("Timeout waiting for YubiKey to become ready to receive")

    def _send_frame(self, buf):
        """Sends a 70 byte frame"""
        prog_seq = self._receive()[STATUS_OFFSET_PROG_SEQ]
        seq = 0
        while buf:
            report, buf = buf[:FEATURE_RPT_DATA_SIZE], buf[FEATURE_RPT_DATA_SIZE:]
            if _should_send(report, seq):
                report += struct.pack(">B", 0x80 | seq)
                self._await_ready_to_write()
                self.connection.send(report)
            seq += 1

        return prog_seq

    def _read_frame(self, prog_seq, event, on_keepalive):
        """Reads one frame"""
        response = b""
        seq = 0
        needs_touch = False

        try:
            while True:
                report = self._receive()
                status_byte = report[FEATURE_RPT_DATA_SIZE]
                if (status_byte & RESP_PENDING_FLAG) != 0:  # Response packet
                    if seq == (status_byte & SEQUENCE_MASK):
                        # Correct sequence
                        response += report[:FEATURE_RPT_DATA_SIZE]
                        seq += 1
                    elif 0 == (status_byte & SEQUENCE_MASK):
                        # Transmission complete
                        self._reset_state()
                        return response
                elif status_byte == 0:  # Status response
                    next_prog_seq = report[STATUS_OFFSET_PROG_SEQ]
                    if response:
                        raise Exception("Incomplete transfer")
                    elif next_prog_seq == prog_seq + 1 or (
                        prog_seq > 0
                        and next_prog_seq == 0
                        and report[STATUS_OFFSET_TOUCH_LOW] & CONFIG_STATUS_MASK == 0
                    ):  # Note: If no valid configurations exist, prog_seq resets to 0.
                        # Sequence updated, return status.
                        return report[1:-1]
                    elif needs_touch:
                        raise TimeoutError("Timed out waiting for touch")
                    else:
                        raise CommandRejectedError("No data")
                else:  # Need to wait
                    if (status_byte & RESP_TIMEOUT_WAIT_FLAG) != 0:
                        on_keepalive(STATUS_UPNEEDED)
                        needs_touch = True
                        timeout = 0.1
                    else:
                        on_keepalive(STATUS_PROCESSING)
                        timeout = 0.02
                    sleep(timeout)
                    if event.wait(timeout):
                        self._reset_state()
                        raise TimeoutError("Command cancelled by Event")
        except KeyboardInterrupt:
            logger.debug("Keyboard interrupt, reset state...")
            self._reset_state()
            raise

    def _reset_state(self):
        """Reset the state of YubiKey from reading"""
        self.connection.send(b"\xff".rjust(FEATURE_RPT_SIZE, b"\0"))
