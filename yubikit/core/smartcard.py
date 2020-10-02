from __future__ import absolute_import

import abc
import struct
from time import time
from enum import IntEnum, unique

from . import INTERFACE, CommandError, ApplicationNotAvailableError


class SmartCardConnection(abc.ABC):
    def close(self):
        """Close the device, releasing any held resources."""

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()

    @property
    @abc.abstractmethod
    def interface(self):
        """Get the interface type of the connection (USB or NFC)"""

    @abc.abstractmethod
    def send_and_receive(self, apdu):
        """Sends a command APDU and returns the response"""


class ApduError(CommandError):
    """Thrown when an APDU response has the wrong SW code"""

    def __init__(self, data, sw):
        self.data = data
        self.sw = sw

    def __str__(self):
        return "APDU error: SW=0x{:04x}".format(self.sw)


@unique
class SW(IntEnum):
    NO_INPUT_DATA = 0x6285
    VERIFY_FAIL_NO_RETRY = 0x63C0
    WRONG_LENGTH = 0x6700
    SECURITY_CONDITION_NOT_SATISFIED = 0x6982
    AUTH_METHOD_BLOCKED = 0x6983
    DATA_INVALID = 0x6984
    CONDITIONS_NOT_SATISFIED = 0x6985
    COMMAND_NOT_ALLOWED = 0x6986
    INCORRECT_PARAMETERS = 0x6A80
    FILE_NOT_FOUND = 0x6A82
    NO_SPACE = 0x6A84
    INVALID_INSTRUCTION = 0x6D00
    COMMAND_ABORTED = 0x6F00
    OK = 0x9000


INS_SELECT = 0xA4
P1_SELECT = 0x04
P2_SELECT = 0x00

INS_SEND_REMAINING = 0xC0
SW1_HAS_MORE_DATA = 0x61

SHORT_APDU_MAX_CHUNK = 0xFF


def _encode_apdu(cla, ins, p1, p2, data=b""):
    data_len = len(data)
    buf = struct.pack(">BBBB", cla, ins, p1, p2)
    if data_len <= SHORT_APDU_MAX_CHUNK:
        if data_len > 0:
            buf += struct.pack(">B", data_len)
    else:
        buf += struct.pack(">BH", 0, data_len)
    return buf + data


class SmartCardProtocol(object):
    def __init__(self, smartcard_connection, ins_send_remaining=INS_SEND_REMAINING):
        self.connection = smartcard_connection
        self._ins_send_remaining = ins_send_remaining
        self._touch_workaround = False
        self._last_long_resp = 0

    def close(self):
        self.connection.close()

    def enable_touch_workaround(self, version):
        self._touch_workaround = self.connection.interface == INTERFACE.USB and (
            (4, 2, 0,) <= version <= (4, 2, 6)
        )

    def select(self, aid):
        try:
            return self.send_apdu(0, INS_SELECT, P1_SELECT, P2_SELECT, aid)
        except ApduError as e:
            if e.sw in (SW.FILE_NOT_FOUND, SW.INVALID_INSTRUCTION):
                raise ApplicationNotAvailableError()
            raise

    def send_apdu(self, cla, ins, p1, p2, data=b""):
        if (
            self._touch_workaround
            and self._last_long_resp > 0
            and time() - self._last_long_resp < 2
        ):
            self.connection.send_and_receive(
                _encode_apdu(0, 0, 0, 0)
            )  # Dummy APDU, returns error
            self._last_long_resp = 0

        # Read first response APDU
        response, sw = self.connection.send_and_receive(
            _encode_apdu(cla, ins, p1, p2, data)
        )

        # Read full response
        buf = b""
        get_data = _encode_apdu(0, self._ins_send_remaining, 0, 0)
        while sw >> 8 == SW1_HAS_MORE_DATA:
            buf += response
            response, sw = self.connection.send_and_receive(get_data)

        if sw != SW.OK:
            raise ApduError(response, sw)
        buf += response

        if self._touch_workaround and len(buf) > 54:
            self._last_long_resp = time()
        else:
            self._last_long_resp = 0

        return buf
