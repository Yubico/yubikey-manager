from __future__ import absolute_import

from ..yubikit.core import TRANSPORT, YUBIKEY, YubiKeyDevice
from ..yubikit.core.iso7816 import Iso7816Connection

from smartcard import System
from smartcard.Exceptions import CardConnectionException
from smartcard.pcsc.PCSCExceptions import ListReadersException
from smartcard.pcsc.PCSCContext import PCSCContext
from fido2.pcsc import CtapPcscDevice

from time import sleep
import subprocess  # nosec


YK_READER_NAME = "yubico yubikey"


# Figure out what the PID should be based on the reader name
def _pid_from_name(name):
    if YK_READER_NAME not in name.lower():
        return None

    transports = 0
    for t in TRANSPORT:
        if t.name in name:
            transports += t

    if "U2F" in name:
        transports += TRANSPORT.FIDO

    key_type = YUBIKEY.NEO if "NEO" in name else YUBIKEY.YK4
    return key_type.get_pid(transports)


class ScardDevice(YubiKeyDevice):
    """YubiKey Smart card device"""

    def __init__(self, reader):
        super(ScardDevice, self).__init__(reader.name, _pid_from_name(reader.name))
        self.reader = reader

    def open_iso7816_connection(self):
        """Open an ISO7816 connection"""
        try:
            return ScardIso7816Connection(self.reader.createConnection())
        except CardConnectionException:
            if kill_scdaemon():
                return ScardIso7816Connection(self.reader.createConnection())
        raise Exception("Unable to connect to smart card")

    @property
    def has_fido(self):
        return YK_READER_NAME not in self.reader.name.lower()

    def open_ctap_device(self):
        """Open a python-fido2 CtapDevice"""
        return CtapPcscDevice(self.reader.createConnection(), self.reader.name)


class ScardIso7816Connection(Iso7816Connection):
    def __init__(self, connection):
        self.connection = connection
        connection.connect()

    def close(self):
        self.connection.disconnect()

    def transceive(self, apdu):
        """Sends a command APDU and returns the response data and sw"""
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        return bytes(bytearray(data)), sw1 << 8 | sw2


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
            devices.append(ScardDevice(reader))
    return devices
