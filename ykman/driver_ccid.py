# Copyright (c) 2015 Yubico AB
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


import struct
import subprocess
import time
import six
from smartcard import System
from smartcard.Exceptions import CardConnectionException
from smartcard.pcsc.PCSCExceptions import ListReadersException
from smartcard.pcsc.PCSCContext import PCSCContext
from .driver import AbstractDriver, ModeSwitchError
from .util import AID, CAPABILITY, TRANSPORT

SW_OK = 0x9000
SW_APPLICATION_NOT_FOUND = 0x6a82

INS_SELECT = 0xa4
INS_YK4_CAPABILITIES = 0x1d

INS_YK2_REQ = 0x01
SLOT_DEVICE_SERIAL = 0x10
SLOT_DEVICE_CONFIG = 0x11

INS_NEO_TEST = 0x16


KNOWN_APPLETS = {
    AID.OTP: CAPABILITY.OTP,
    b'\xa0\x00\x00\x06\x47\x2f\x00\x01': CAPABILITY.U2F,  # Official
    b'\xa0\x00\x00\x05\x27\x10\x02': CAPABILITY.U2F,  # Yubico - No longer used
    AID.PIV: CAPABILITY.PIV,
    AID.OPGP: CAPABILITY.OPGP,
    AID.OATH: CAPABILITY.OATH
}


class CCIDError(Exception):
    """Thrown when smart card communication fails."""


class APDUError(CCIDError):
    """Thrown when an APDU response has the wrong SW code"""

    def __init__(self, data, sw):
        self.data = data
        self.sw = sw

    def __str__(self):
        return 'APDU error: SW=0x{:04x}'.format(self.sw)


class CCIDDriver(AbstractDriver):
    """
    Pyscard based CCID driver
    """
    transport = TRANSPORT.CCID

    def __init__(self, connection, name=''):
        self._conn = connection
        try:
            self._read_serial()
        except APDUError:
            pass  # Can't read serial

    def _read_serial(self):
        self.send_apdu(0, INS_SELECT, 4, 0, AID.OTP)
        serial = self.send_apdu(0, INS_YK2_REQ, SLOT_DEVICE_SERIAL, 0)
        if len(serial) == 4:
            self._serial = struct.unpack('>I', serial)[0]

    def read_capabilities(self):
        try:
            self.send_apdu(0, INS_SELECT, 4, 0, AID.MGR)
            capa = self.send_apdu(0, INS_YK4_CAPABILITIES, 0, 0)
            return capa
        except APDUError:
            return b''

    def probe_capabilities_support(self):
        capa = CAPABILITY.CCID
        for aid, code in KNOWN_APPLETS.items():
            try:
                self.send_apdu(0, INS_SELECT, 4, 0, aid)
                capa |= code
            except APDUError:
                pass
        return capa

    def send_apdu(self, cl, ins, p1, p2, data=b'', check=SW_OK):
        header = [cl, ins, p1, p2, len(data)]
        body = list(six.iterbytes(data))
        try:
            resp, sw1, sw2 = self._conn.transmit(header + body)
        except CardConnectionException as e:
            raise CCIDError(e)
        sw = sw1 << 8 | sw2
        resp = bytes(bytearray(resp))
        if check is None:
            return resp, sw
        elif check == sw:
            return resp
        else:
            raise APDUError(resp, sw)

    def select(self, aid):
        return self.send_apdu(0, INS_SELECT, 0x04, 0, aid)

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        mode_data = struct.pack('BBH', mode_code, cr_timeout, autoeject_time)
        try:
            try:
                self._set_mode_otp(mode_data)
            except APDUError:
                self._set_mode_mgr(mode_data)
        except CCIDError:
            raise ModeSwitchError()

    def _set_mode_otp(self, mode_data):
        resp = self.send_apdu(0, INS_SELECT, 4, 0, AID.OTP)
        pgm_seq_old = six.indexbytes(resp, 3)
        resp = self.send_apdu(0, INS_YK2_REQ, SLOT_DEVICE_CONFIG, 0, mode_data)
        pgm_seq_new = six.indexbytes(resp, 3)
        if not _pgm_seq_ok(pgm_seq_old, pgm_seq_new):
            raise ModeSwitchError()

    def _set_mode_mgr(self, mode_data):
        self.send_apdu(0, INS_SELECT, 4, 0, AID.MGR)
        self.send_apdu(0, INS_NEO_TEST, SLOT_DEVICE_CONFIG, 0, mode_data)

    def __del__(self):
        try:
            self._conn.disconnect()
        except:
            pass  # Ignore


def _pgm_seq_ok(pgm_seq_old, pgm_seq_new):
    return pgm_seq_new == pgm_seq_old == 0 or pgm_seq_new > pgm_seq_old


def kill_scdaemon():
    killed = False
    try:
        # Works for Windows.
        from win32com.client import GetObject
        from win32api import OpenProcess, CloseHandle, TerminateProcess
        wmi = GetObject('winmgmts:')
        ps = wmi.InstancesOf('Win32_Process')
        for p in ps:
            if p.Properties_('Name').Value == 'scdaemon.exe':
                pid = p.Properties_('ProcessID').Value
                handle = OpenProcess(1, False, pid)
                TerminateProcess(handle, -1)
                CloseHandle(handle)
                killed = True
    except ImportError:
        # Works for Linux and OS X.
        pids = subprocess.check_output(
            "ps ax | grep scdaemon | grep -v grep | awk '{ print $1 }'",
            shell=True).strip()
        if pids:
            for pid in pids.split():
                subprocess.call(['kill', '-9', pid])
            killed = True

    if killed:
        time.sleep(0.1)
    return killed


def _list_readers():
    try:
        return System.readers()
    except ListReadersException:
        # If the PCSC system has restarted the context might be stale, try
        # forcing a new context (This happens on Windows if the last reader is
        # removed):
        PCSCContext.instance = None
        return System.readers()


def open_device():
    for reader in _list_readers():
        if reader.name.lower().startswith('yubico yubikey'):
            try:
                conn = reader.createConnection()
                conn.connect()
            except CardConnectionException:
                if kill_scdaemon():
                    return open_device()
                raise
            return CCIDDriver(conn, reader.name)
