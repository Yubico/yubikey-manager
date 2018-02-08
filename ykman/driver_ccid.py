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

from __future__ import absolute_import

import logging
import struct
import subprocess
import time
import six
from smartcard import System
from smartcard.Exceptions import CardConnectionException
from smartcard.pcsc.PCSCExceptions import ListReadersException
from smartcard.pcsc.PCSCContext import PCSCContext
from .driver import AbstractDriver, ModeSwitchError
from .util import AID, CAPABILITY, TRANSPORT, YUBIKEY

SW_OK = 0x9000
SW_APPLICATION_NOT_FOUND = 0x6a82
SW_NO_INPUT_DATA = 0x6285
SW_CONDITIONS_NOT_SATISFIED = 0x6985

INS_SELECT = 0xa4
INS_YK4_CAPABILITIES = 0x1d

INS_YK2_REQ = 0x01
SLOT_DEVICE_SERIAL = 0x10
SLOT_DEVICE_CONFIG = 0x11

INS_NEO_TEST = 0x16


KNOWN_APPLETS = {
    AID.OTP: CAPABILITY.OTP,
    AID.U2F: CAPABILITY.U2F,
    AID.U2F_YUBICO: CAPABILITY.U2F,
    AID.PIV: CAPABILITY.PIV,
    AID.OPGP: CAPABILITY.OPGP,
    AID.OATH: CAPABILITY.OATH
}

logger = logging.getLogger(__name__)


class CCIDError(Exception):
    """Thrown when smart card communication fails."""


class APDUError(CCIDError):
    """Thrown when an APDU response has the wrong SW code"""

    def __init__(self, data, sw):
        self.data = data
        self.sw = sw

    def __str__(self):
        return 'APDU error: SW=0x{:04x}'.format(self.sw)


def _pid_from_name(name):
    transports = 0
    for t in TRANSPORT:
        if t.name in name:
            transports += t

    key_type = YUBIKEY.NEO if 'NEO' in name else YUBIKEY.YK4
    return key_type.get_pid(transports)


class CCIDDriver(AbstractDriver):
    """
    Pyscard based CCID driver
    """
    transport = TRANSPORT.CCID

    def __init__(self, connection, name):
        self._conn = connection
        self._pid = _pid_from_name(name)
        try:
            self._read_version()
        except APDUError as e:
            logger.error('Failed to read firmware version', exc_info=e)
        try:
            self._read_serial()
        except APDUError as e:
            logger.error('Failed to read serial number', exc_info=e)

    def _read_version(self):
        s = self.send_apdu(0, INS_SELECT, 4, 0, AID.OTP)
        self._version = tuple(c for c in six.iterbytes(s[:3]))

    def _read_serial(self):
        serial = self.send_apdu(0, INS_YK2_REQ, SLOT_DEVICE_SERIAL, 0)
        if len(serial) == 4:
            self._serial = struct.unpack('>I', serial)[0]

    def guess_version(self):
        return self._version, self.key_type != YUBIKEY.NEO

    def read_capabilities(self):
        try:
            self.send_apdu(0, INS_SELECT, 4, 0, AID.MGR)
            capa = self.send_apdu(0, INS_YK4_CAPABILITIES, 0, 0)
            return capa
        except APDUError as e:
            logger.error('Failed to read capabilities', exc_info=e)
            return b''

    def probe_capabilities_support(self):
        capa = CAPABILITY.CCID
        for aid, code in KNOWN_APPLETS.items():
            try:
                self.send_apdu(0, INS_SELECT, 4, 0, aid)
                capa |= code
                logger.debug(
                    'Found applet: aid: %s , capability: %s', aid, code)
            except APDUError:
                logger.debug(
                    'Missing applet: aid: %s , capability: %s', aid, code)
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
        except Exception as e:
            logger.debug('Exception in destructor', exc_info=e)


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


def open_devices(name_filter='yubico yubikey'):
    readers = _list_readers()
    while readers:
        try_again = []
        for reader in readers:
            if reader.name.lower().startswith(name_filter):
                try:
                    conn = reader.createConnection()
                    conn.connect()
                    yield CCIDDriver(conn, reader.name)
                except CardConnectionException:
                    try_again.append(reader)
                except Exception as e:
                    # Try with next reader.
                    logger.debug(
                        'Failed to connect to reader %s', reader, exc_info=e)
        if try_again and kill_scdaemon():
            readers = try_again
        else:
            return
