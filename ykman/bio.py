# Copyright (c) 2018 Yubico AB
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

from .util import AID
from .driver_ccid import APDUError, SW
from enum import IntEnum, unique
import logging
import struct


logger = logging.getLogger(__name__)


@unique
class INS(IntEnum):
    DEBUG = 0x20
    # SLE = 0x21
    # STM = 0x22
    SLE_VERSION = 0x0C
    STM_VERSION = 0x0D


INS_GET_RESPONSE = 0xC0


@unique
class P1(IntEnum):
    DUMP_STM = 0x21
    DUMP_SLE = 0x22
    CLEAR_LOGS = 0x28
    OPEN = 0x2A
    CLOSE = 0x2B


class BioController(object):
    def __init__(self, driver):
        self._driver = driver
        driver.select(AID.MGR)

    def clear_logs(self):
        self.send_cmd(INS.DEBUG, P1.CLEAR_LOGS)

    def read_sle_version(self):
        return self.send_cmd(INS.SLE_VERSION).decode('utf8')

    def read_stm_version(self):
        return self.send_cmd(INS.STM_VERSION).decode('utf8')

    def send_cmd(self, ins, p1=0, p2=0, data=b'', check=SW.OK):
        while len(data) > 0xFF:
            self._driver.send_apdu(0x10, ins, p1, p2, data[:0xFF])
            data = data[0xFF:]
        resp, sw = self._driver.send_apdu(0, ins, p1, p2, data, check=None)

        while (sw >> 8) == SW.MORE_DATA:
            more, sw = self._driver.send_apdu(
                0, INS_GET_RESPONSE, 0, 0, b'', check=None
            )
            resp += more

        if check is None:
            return resp, sw
        elif sw != check:
            raise APDUError(resp, sw)

        return resp

    def dump_sle(self):
        resp = b''

        while True:
            data = self.send_cmd(INS.DEBUG, P1.DUMP_SLE)
            if not data:
                break
            resp += data

        lines = []

        while resp:
            lines.append(struct.unpack_from('!HHHHHBBBB', resp))
            resp = resp[14:]

        return lines

    def dump_stm(self):
        # self.send_cmd(INS.DUMP_STM)  # No longer needed
        resp = b''

        while True:
            try:
                data = self.send_cmd(INS.DEBUG, P1.DUMP_STM)
            except APDUError as e:
                # Once done, we'll get an empty response with SW = MORE_DATA, which
                # causes a GET_RESPONSE that results in this error. So we just stop.
                if e.sw == 0x6D00:
                    break
                raise

            if not data:
                break
            resp += data

        lines = []
        while resp:
            lines.append(struct.unpack_from('<HHHBBBBBBHH', resp))
            resp = resp[16:]

        return lines

    def dump_logs(self, logfile):
        sle_v = self.read_sle_version()
        stm_v = self.read_stm_version()
        logfile.write('# YubiKey BIO log dump\n')

        logfile.write('# {}\n'.format(sle_v))
        logfile.write(
            '# Session ID, Duration, SPI Dur., I2C Dur., FPS Dur., Command, Error, ' 'Enrollments, Flags\n'
        )
        for line in self.dump_sle():
            logfile.write(
                '0x{:04x},0x{:04x},0x{:04x},0x{:04x},0x{:04x},0x{:02x},'
                '0x{:02x},0x{:02x},0x{:02x}\n'.format(*line)
            )

        logfile.write('# {}\n'.format(stm_v))
        logfile.write(
            '# Session ID, Duration, Capture Dur., Command, Result, Last Enroll, '
            'Samples Remaining, Error, Vendor Error, Flags, Reserved\n'
        )
        for line in self.dump_stm():
            logfile.write(
                '0x{:04x},0x{:04x},0x{:04x},0x{:02x},0x{:02x},0x{:02x},'
                '0x{:02x},0x{:02x},0x{:02x},0x{:04x},0x{:04x}\n'.format(*line)
            )
