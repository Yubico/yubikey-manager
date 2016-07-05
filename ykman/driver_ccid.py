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
from smartcard import System
from smartcard.Exceptions import CardConnectionException
from .driver import AbstractDriver, ModeSwitchError
from .util import Mode, CAPABILITY, TRANSPORT, read_version_usb
from .yubicommon.compat import byte2int, int2byte

SW_OK = 0x9000

INS_SELECT = 0xa4
INS_YK4_CAPABILITIES = 0x1d

INS_YK2_REQ = 0x01
SLOT_DEVICE_SERIAL = 0x10
SLOT_DEVICE_CONFIG = 0x11

INS_NEO_TEST = 0x16

OTP_AID = b'\xa0\x00\x00\x05\x27\x20\x01'
MGR_AID = b'\xa0\x00\x00\x05\x27\x47\x11\x17'
OPGP_AID = b'\xd2\x76\x00\x01\x24\x01'

KNOWN_APPLETS = {
    OTP_AID: CAPABILITY.OTP,
    b'\xa0\x00\x00\x06\x47\x2f\x00\x01': CAPABILITY.U2F,  # Official
    b'\xa0\x00\x00\x05\x27\x10\x02': CAPABILITY.U2F,  # Yubico - No longer used
    b'\xa0\x00\x00\x03\x08': CAPABILITY.PIV,
    OPGP_AID: CAPABILITY.OPGP,
    b'\xa0\x00\x00\x05\x27\x21\x01': CAPABILITY.OATH
}


class CCIDError(Exception):
    """Thrown when smart card communication fails."""

    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return 'CCID error: {}'.format(self.errno)


class CCIDDriver(AbstractDriver):
    """
    Pyscard based CCID driver
    """
    transport = TRANSPORT.CCID

    def __init__(self, connection, name=''):
        self._conn = connection
        self._mode = Mode(sum(t for t in TRANSPORT if t.name in name))
        self._version = read_version_usb()
        try:
            self._read_serial()
        except CCIDError:
            pass  # Can't read serial

    def _read_serial(self):
        self.send_apdu(0, INS_SELECT, 4, 0, OTP_AID)
        serial = self.send_apdu(0, INS_YK2_REQ, SLOT_DEVICE_SERIAL, 0)
        if len(serial) == 4:
            self._serial = struct.unpack('>I', serial)[0]

    def read_capabilities(self):
        if self.version == (4, 2, 4):  # 4.2.4 doesn't report correctly.
            return b'\x03\x01\x01\x3f'
        try:
            self.send_apdu(0, INS_SELECT, 4, 0, MGR_AID)
            capa = self.send_apdu(0, INS_YK4_CAPABILITIES, 0, 0)
            return capa
        except CCIDError:
            return b''

    def probe_capabilities_support(self):
        capa = CAPABILITY.CCID
        for aid, code in KNOWN_APPLETS.items():
            try:
                self.send_apdu(0, INS_SELECT, 4, 0, aid)
                capa |= code
            except CCIDError:
                pass
        return capa

    def send_apdu(self, cl, ins, p1, p2, data=b'', check=True):
        header = [cl, ins, p1, p2, len(data)]
        body = [byte2int(c) for c in data]
        try:
            resp, sw1, sw2 = self._conn.transmit(header + body)
        except CardConnectionException as e:
            raise CCIDError(e)
        sw = sw1 << 8 | sw2
        if check and sw != SW_OK:
            raise CCIDError(sw)
        return b''.join([int2byte(c) for c in resp])

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        mode_data = struct.pack('BBH', mode_code, cr_timeout, autoeject_time)
        try:
            try:
                self._set_mode_otp(mode_data)
            except CCIDError:
                self._set_mode_mgr(mode_data)
        except CCIDError:
            raise ModeSwitchError()

    def _set_mode_otp(self, mode_data):
        resp = self.send_apdu(0, INS_SELECT, 4, 0, OTP_AID)
        pgm_seq_old = byte2int(resp[3])
        resp = self.send_apdu(0, INS_YK2_REQ, SLOT_DEVICE_CONFIG, 0, mode_data)
        pgm_seq_new = byte2int(resp[3])
        if not _pgm_seq_ok(pgm_seq_old, pgm_seq_new):
            raise ModeSwitchError()

    def _set_mode_mgr(self, mode_data):
        self.send_apdu(0, INS_SELECT, 4, 0, MGR_AID)
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
        WMI = GetObject('winmgmts:')
        ps = WMI.InstancesOf('Win32_Process')
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
        print("scdaemon stopped...")
        time.sleep(0.1)
    return killed


def open_device():
    for reader in System.readers():
        if reader.name.lower().startswith('yubico yubikey'):
            try:
                conn = reader.createConnection()
                conn.connect()
            except CardConnectionException as e:
                if 'Sharing violation' in str(e) and kill_scdaemon():
                    return open_device()
                raise
            return CCIDDriver(conn, reader.name)
