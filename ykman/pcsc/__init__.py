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

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import USB_INTERFACE
from ..base import YUBIKEY, YkmanDevice

from smartcard import System
from smartcard.Exceptions import CardConnectionException
from smartcard.pcsc.PCSCExceptions import ListReadersException
from smartcard.pcsc.PCSCContext import PCSCContext

from fido2.pcsc import CtapPcscDevice
from time import sleep
import subprocess  # nosec
import logging

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
    return key_type.get_pid(interfaces)


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
        if issubclass(CtapPcscDevice, connection_type):
            return self.transport == TRANSPORT.NFC
        return issubclass(ScardSmartCardConnection, connection_type)

    def open_connection(self, connection_type):
        if issubclass(ScardSmartCardConnection, connection_type):
            return self._open_smartcard_connection()
        elif issubclass(CtapPcscDevice, connection_type):
            if self.transport == TRANSPORT.NFC:
                return CtapPcscDevice(self.reader.createConnection(), self.reader.name)
        return super(ScardYubiKeyDevice, self).open_connection(connection_type)

    def _open_smartcard_connection(self) -> SmartCardConnection:
        try:
            return ScardSmartCardConnection(self.reader.createConnection())
        except CardConnectionException as e:
            if kill_scdaemon():
                return ScardSmartCardConnection(self.reader.createConnection())
            raise e


class ScardSmartCardConnection(SmartCardConnection):
    def __init__(self, connection):
        self.connection = connection
        connection.connect()
        atr = connection.getATR()
        self._transport = TRANSPORT.USB if atr[1] & 0xF0 == 0xF0 else TRANSPORT.NFC

    @property
    def transport(self):
        return self._transport

    def close(self):
        self.connection.disconnect()

    def send_and_receive(self, apdu):
        """Sends a command APDU and returns the response data and sw"""
        logger.debug("SEND: %s", apdu.hex())
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        logger.debug("RECV: %s SW=%02x%02x", bytes(data).hex(), sw1, sw2)
        return bytes(data), sw1 << 8 | sw2


def kill_scdaemon():
    killed = False
    try:
        # Works for Windows.
        from win32com.client import GetObject
        from win32api import OpenProcess, CloseHandle, TerminateProcess

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
        return_code = subprocess.call(["/usr/bin/pkill", "-9", "scdaemon"])  # nosec
        if return_code == 0:
            killed = True
    if killed:
        sleep(0.1)
    return killed


def list_readers():
    try:
        return System.readers()
    except ListReadersException:
        # If the PCSC system has restarted the context might be stale, try
        # forcing a new context (This happens on Windows if the last reader is
        # removed):
        PCSCContext.instance = None
        return System.readers()


def list_devices(name_filter=None):
    name_filter = name_filter or YK_READER_NAME
    devices = []
    for reader in list_readers():
        if name_filter.lower() in reader.name.lower():
            devices.append(ScardYubiKeyDevice(reader))
    return devices
