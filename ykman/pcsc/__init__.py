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
import os
import subprocess  # nosec
from time import sleep

from smartcard import System
from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
from smartcard.pcsc.PCSCExceptions import ListReadersException

from yubikit.core import PID, TRANSPORT, YUBIKEY
from yubikit.core.fido import SmartCardCtapDevice
from yubikit.core.smartcard import SmartCardConnection
from yubikit.logging import LOG_LEVEL
from yubikit.management import USB_INTERFACE

from ..base import YkmanDevice

logger = logging.getLogger(__name__)


YK_READER_NAME = "yubico yubikey"
_YKMAN_NO_EXCLUSIVE = "YKMAN_NO_EXLUSIVE"


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


def _release(connection):
    if hasattr(connection, "release"):
        connection.release()


class ScardSmartCardConnection(SmartCardConnection):
    def __init__(self, connection):
        connection.connect()
        self.connection = connection

        atr = self.connection.getATR()
        self._transport = (
            TRANSPORT.USB if atr and atr[1] & 0xF0 == 0xF0 else TRANSPORT.NFC
        )

    @property
    def transport(self):
        return self._transport

    def close(self):
        self.connection.disconnect()
        _release(self.connection)

    def send_and_receive(self, apdu):
        """Sends a command APDU and returns the response data and sw"""
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", apdu.hex())
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        logger.log(
            LOG_LEVEL.TRAFFIC, "RECV: %s SW=%02x%02x", bytes(data).hex(), sw1, sw2
        )
        return bytes(data), sw1 << 8 | sw2


class ScardYubiKeyDevice(YkmanDevice):
    """YubiKey Smart card device"""

    def __init__(self, reader):
        # Base transport on reader name: NFC readers will have a different name
        if YK_READER_NAME in reader.name.lower():
            transport = TRANSPORT.USB
        else:
            transport = TRANSPORT.NFC
        super(ScardYubiKeyDevice, self).__init__(
            transport, reader.name, _pid_from_name(reader.name)
        )
        self.reader = reader

    def supports_connection(self, connection_type):
        if issubclass(SmartCardCtapDevice, connection_type):
            return self.transport == TRANSPORT.NFC
        return issubclass(ScardSmartCardConnection, connection_type)

    def open_connection(self, connection_type):
        if issubclass(ScardSmartCardConnection, connection_type):
            return self._open_smartcard_connection()
        elif issubclass(SmartCardCtapDevice, connection_type):
            if self.transport == TRANSPORT.NFC:
                return SmartCardCtapDevice(self._open_smartcard_connection())
        return super(ScardYubiKeyDevice, self).open_connection(connection_type)

    def _open_smartcard_connection(self, retry=True) -> SmartCardConnection:
        connection = self.reader.createConnection()
        try:
            # Try an exclusive connection, unless disabled
            if os.environ.get(_YKMAN_NO_EXCLUSIVE) is None:
                excl_connection = ExclusiveConnectCardConnection(connection)
                try:
                    scard_conn = ScardSmartCardConnection(excl_connection)
                    logger.debug("Using exclusive CCID connection")
                    return scard_conn
                except CardConnectionException:
                    logger.info("Failed to get exclusive CCID access")

            # Try a shared connection
            return ScardSmartCardConnection(connection)
        except CardConnectionException:
            _release(connection)
            # Neither connection worked, maybe we need to kill stuff
            if retry and (kill_scdaemon() or kill_yubikey_agent()):
                return self._open_smartcard_connection(False)
            raise
        except (NoCardException, ValueError):
            _release(connection)
            # Handle reclaim timeout
            # TODO: Maybe only on NEO?
            if retry and self.transport == TRANSPORT.USB:
                for _ in range(6):
                    try:
                        sleep(0.5)
                        return self._open_smartcard_connection(False)
                    except (NoCardException, ValueError):
                        continue
            raise


def kill_scdaemon():
    killed = False
    try:
        # Works for Windows.
        from win32api import CloseHandle, OpenProcess, TerminateProcess
        from win32com.client import GetObject

        wmi = GetObject("winmgmts:")
        ps = wmi.InstancesOf("Win32_Process")
        for p in ps:
            if p.Properties_("Name").Value == "scdaemon.exe":
                pid = p.Properties_("ProcessID").Value
                handle = OpenProcess(1, False, pid)
                TerminateProcess(handle, -1)
                CloseHandle(handle)
                killed = True
    except ImportError:
        # Works for Linux and OS X.
        return_code = subprocess.call(["pkill", "-9", "scdaemon"])  # nosec
        if return_code == 0:
            killed = True
    if killed:
        sleep(0.1)
    return killed


def kill_yubikey_agent():
    killed = False
    return_code = subprocess.call(["pkill", "-HUP", "yubikey-agent"])  # nosec
    if return_code == 0:
        killed = True
    if killed:
        sleep(0.1)

    return killed


def list_readers():
    try:
        return System.readers()
    except ListReadersException as e:
        # If the PCSC system has restarted the context might be stale, try
        # forcing a new context (This happens on Windows if the last reader is
        # removed):
        try:
            from smartcard.pcsc.PCSCContext import PCSCContext

            PCSCContext.instance = None
            return System.readers()
        except ImportError:
            # As of pyscard 2.2.2 the PCSCContext singleton has been removed
            raise e


def list_devices(name_filter=None):
    name_filter = YK_READER_NAME if name_filter is None else name_filter
    devices = []
    for reader in list_readers():
        if name_filter.lower() in reader.name.lower():
            devices.append(ScardYubiKeyDevice(reader))
    return devices
