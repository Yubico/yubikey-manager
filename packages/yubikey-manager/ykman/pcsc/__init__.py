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

import logging

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.logging import LOG_LEVEL

from _yubikit_native.pcsc import PcscConnection
from _yubikit_native.pcsc import list_readers as _native_list_readers

logger = logging.getLogger(__name__)


YK_READER_NAME = "yubico yubikey"


class ScardSmartCardConnection(SmartCardConnection):
    def __init__(self, reader_name):
        # PcscConnection.open() handles exclusive→shared fallback and
        # killing scdaemon/yubikey-agent if they block access.
        self._native = PcscConnection.open(reader_name)
        self._transport = (
            TRANSPORT.USB if self._native.transport == "usb" else TRANSPORT.NFC
        )

    @property
    def transport(self):
        return self._transport

    def close(self):
        self._native.disconnect()

    def send_and_receive(self, apdu):
        """Sends a command APDU and returns the response data and sw"""
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", apdu.hex())
        resp = self._native.transmit(apdu)
        data = resp[:-2]
        sw = resp[-2] << 8 | resp[-1]
        logger.log(LOG_LEVEL.TRAFFIC, "RECV: %s SW=%04x", data.hex(), sw)
        return bytes(data), sw


def list_readers():
    try:
        return _native_list_readers()
    except OSError:
        return []
