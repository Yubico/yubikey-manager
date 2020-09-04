from __future__ import absolute_import

import abc
import struct
from time import time

from . import CommandError, ApplicationNotAvailableError


class Iso7816Connection(abc.ABC):
    def close(self):
        """Close the device, releasing any held resources."""

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()

    @abc.abstractmethod
    def transceive(self, apdu):
        """Sends a command APDU and returns the response"""


class ApduError(CommandError):
    """Thrown when an APDU response has the wrong SW code"""

    def __init__(self, data, sw):
        self.data = data
        self.sw = sw

    def __str__(self):
        return "APDU error: SW=0x{:04x}".format(self.sw)


INS_SELECT = 0xA4
P1_SELECT = 0x04
P2_SELECT = 0x00
INS_SEND_REMAINING = 0xC0

SW_SUCCESS = 0x9000
SW_FILE_NOT_FOUND = 0x6A82
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


class Iso7816Application(object):
    def __init__(self, aid, iso7816_connection, ins_send_remaining=INS_SEND_REMAINING):
        self.aid = aid
        self.connection = iso7816_connection
        self._ins_send_remaining = ins_send_remaining
        self._touch_workaround = False
        self._last_long_resp = 0

    def close(self):
        self.connection.close()

    def enable_touch_workaround(self, version):
        self._touch_workaround = (4, 2, 0) <= version <= (4, 2, 6)

    def select(self):
        try:
            return self.send_apdu(0, INS_SELECT, P1_SELECT, P2_SELECT, self.aid)
        except ApduError as e:
            if e.sw == SW_FILE_NOT_FOUND:
                raise ApplicationNotAvailableError()
            raise

    def send_apdu(self, cla, ins, p1, p2, data=b""):
        if (
            self._touch_workaround
            and self._last_long_resp > 0
            and time() - self._last_long_resp < 2
        ):
            self.connection.transceive(
                _encode_apdu(0, 0, 0, 0)
            )  # Dummy APDU, returns error
            self._last_long_resp = 0

        # Read first response APDU
        response, sw = self.connection.transceive(_encode_apdu(cla, ins, p1, p2, data))

        # Read full response
        buf = b""
        get_data = _encode_apdu(0, self._ins_send_remaining, 0, 0)
        while sw >> 8 == SW1_HAS_MORE_DATA:
            buf += response
            response, sw = self.connection.transceive(get_data)

        if sw != SW_SUCCESS:
            raise ApduError(response, sw)
        buf += response

        if self._touch_workaround and len(buf) > 54:
            self._last_long_resp = time()
        else:
            self._last_long_resp = 0

        return buf
