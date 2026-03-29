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
from time import sleep

from _yubikit_native.pcsc import PcscConnection
from _yubikit_native.pcsc import list_readers as _native_list_readers
from yubikit.core import PID, TRANSPORT, YUBIKEY
from yubikit.core.fido import SmartCardCtapDevice
from yubikit.core.smartcard import SmartCardConnection
from yubikit.logging import LOG_LEVEL
from yubikit.management import USB_INTERFACE
from yubikit.support import read_info

from ..base import REINSERT_STATUS, CancelledException, YkmanDevice

logger = logging.getLogger(__name__)


YK_READER_NAME = "yubico yubikey"


# Figure out what the PID should be based on the reader name
def _pid_from_name(name):
    if YK_READER_NAME not in name.lower():
        return None

    interfaces = USB_INTERFACE(0)
    for iface in USB_INTERFACE:
        if iface.name in name:
            interfaces |= iface

    if "U2F" in name:
        interfaces |= USB_INTERFACE.FIDO

    key_type = YUBIKEY.NEO if "NEO" in name else YUBIKEY.YK4
    return PID.of(key_type, interfaces)


class ScardSmartCardConnection(SmartCardConnection):
    def __init__(self, reader_name):
        # PcscConnection.open() handles exclusive→shared fallback and
        # killing scdaemon/yubikey-agent if they block access.
        self.connection = PcscConnection.open(reader_name)

        atr = self.connection.get_atr()
        self._transport = (
            TRANSPORT.USB if atr and atr[1] & 0xF0 == 0xF0 else TRANSPORT.NFC
        )

    @property
    def transport(self):
        return self._transport

    def close(self):
        self.connection.disconnect()

    def send_and_receive(self, apdu):
        """Sends a command APDU and returns the response data and sw"""
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", apdu.hex())
        resp = self.connection.transmit(apdu)
        data = resp[:-2]
        sw = resp[-2] << 8 | resp[-1]
        logger.log(LOG_LEVEL.TRAFFIC, "RECV: %s SW=%04x", data.hex(), sw)
        return bytes(data), sw


class ScardYubiKeyDevice(YkmanDevice):
    """YubiKey Smart card device"""

    def __init__(self, reader_name):
        # Base transport on reader name: NFC readers will have a different name
        if YK_READER_NAME in reader_name.lower():
            transport = TRANSPORT.USB
        else:
            transport = TRANSPORT.NFC
        super().__init__(transport, reader_name, _pid_from_name(reader_name))
        self.reader_name = reader_name

    def supports_connection(self, connection_type):
        if issubclass(SmartCardCtapDevice, connection_type):
            return self.transport == TRANSPORT.NFC
        return issubclass(ScardSmartCardConnection, connection_type)

    def open_connection(self, connection_type):
        assert isinstance(connection_type, type)  # noqa: S101
        if issubclass(ScardSmartCardConnection, connection_type):
            return self._open_smartcard_connection()
        elif issubclass(SmartCardCtapDevice, connection_type):
            return SmartCardCtapDevice(self._open_smartcard_connection())
        return super().open_connection(connection_type)

    def _open_smartcard_connection(self) -> SmartCardConnection:
        return ScardSmartCardConnection(self.reader_name)

    def _do_reinsert(self, reinsert_cb, event):
        removed = False
        with self.open_connection(SmartCardConnection) as conn:
            info = read_info(conn, self.pid)
        reinsert_cb(REINSERT_STATUS.REMOVE)

        if self.transport == TRANSPORT.NFC:
            while not event.wait(0.5):
                try:
                    conn = self.open_connection(SmartCardConnection)
                    if removed:
                        info2 = read_info(conn, self.pid)
                        conn.close()
                        if info.serial != info2.serial or info.version != info2.version:
                            raise ValueError(
                                "Reinserted YubiKey does not match the original"
                            )
                        sleep(1.0)  # Wait for the device to settle
                        return
                    conn.close()
                except OSError:
                    if not removed:
                        reinsert_cb(REINSERT_STATUS.REINSERT)
                        removed = True

            raise CancelledException()
        else:
            while not event.wait(0.5):
                if not removed:
                    # Wait for the reader to be removed
                    if self.reader_name not in list_readers():
                        reinsert_cb(REINSERT_STATUS.REINSERT)
                        removed = True
                else:
                    # Wait for the reader to be reinserted
                    for reader_name in list_readers():
                        if reader_name == self.reader_name:
                            with self.open_connection(SmartCardConnection) as conn:
                                info2 = read_info(conn, self.pid)
                            if (
                                info.serial != info2.serial
                                or info.version != info2.version
                            ):
                                raise ValueError(
                                    "Reinserted YubiKey does not match the original"
                                )
                            sleep(1.0)  # Wait for the device to settle
                            return
            raise CancelledException()


def list_readers():
    try:
        return _native_list_readers()
    except OSError:
        return []


def list_devices(name_filter=None):
    name_filter = YK_READER_NAME if name_filter is None else name_filter
    devices = []
    for reader_name in list_readers():
        if name_filter.lower() in reader_name.lower():
            devices.append(ScardYubiKeyDevice(reader_name))
    return devices
