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

from .util import click_postpone_execution
from ..util import AID, TRANSPORT
from ..descriptor import get_descriptors
from ..driver_ccid import APDUError, SW
from time import sleep
from enum import IntEnum, unique
import logging
import click
import struct
import os


logger = logging.getLogger(__name__)


@unique
class INS(IntEnum):
    CLEAR_LOGS = 0x20
    DUMP_SLE = 0x21
    DUMP_STM = 0x22
    SLE_VERSION = 0x0C
    STM_VERSION = 0x0D
    GET_RESPONSE = 0xC0


class FakeBioController(object):
    def __init__(self, driver):
        self._driver = driver
        driver.select(AID.MGR)

    def clear_logs(self):
        pass

    def read_sle_version(self):
        return 'SLE version x.y.z'

    def read_stm_version(self):
        return 'STM32 version x.y.z'

    def dump_sle(self):
        resp = os.urandom(10 * 6)
        lines = []
        while resp:
            lines.append(struct.unpack_from('!HHHBBBB', resp))
            resp = resp[10:]

        return lines

    def dump_stm(self):
        resp = os.urandom(16 * 6)

        lines = []
        while resp:
            lines.append(struct.unpack_from('!HHBBBBBBHI', resp))
            resp = resp[16:]

        return lines


class BioController(object):
    def __init__(self, driver):
        self._driver = driver
        driver.select(AID.MGR)

    def clear_logs(self):
        self.send_cmd(INS.CLEAR_LOGS, 8)

    def read_sle_version(self):
        return self.send_cmd(INS.SLE_VERSION).decode('utf8')

    def read_stm_version(self):
        return self.send_cmd(INS.STM_VERSION).decode('utf8')

    def send_cmd(self, ins, p1=0, p2=0, data=b'', check=SW.OK):
        while len(data) > 0xff:
            self._driver.send_apdu(0x10, ins, p1, p2, data[:0xff])
            data = data[0xff:]
        resp, sw = self._driver.send_apdu(0, ins, p1, p2, data, check=None)

        while (sw >> 8) == SW.MORE_DATA:
            more, sw = self._driver.send_apdu(
                0, INS.GET_RESPONSE, 0, 0, b'', check=None)
            resp += more

        if check is None:
            return resp, sw
        elif sw != check:
            raise APDUError(resp, sw)

        return resp

    def dump_sle(self):
        resp = b''
        while True:
            data = self.send_cmd(INS.DUMP_SLE)
            if not data:
                break
            resp += data

        lines = []

        while resp:
            lines.append(struct.unpack_from('!HHHBBBB', resp))
            resp = resp[10:]

        return lines

    def dump_stm(self):
        self.send_cmd(INS.DUMP_STM)
        resp = b''

        while True:
            data = self.send_cmd(INS.DUMP_STM, 1)
            if not data:
                break
            resp += data

        lines = []
        while resp:
            lines.append(struct.unpack_from('!HHBBBBBBHI', resp))
            resp = resp[16:]

        return lines


@click.group()
@click.pass_context
@click_postpone_execution
def bio(ctx):
    """
    Internal YubiKey BIO commands.

    Examples:

    \b
      Dump logs from the YubiKey to a CSV file.
      $ ykman bio dump-logs

    \b
      Clear all stored logs from the device.
      WARNING: Don't do this without dumping th elogs first!
      $ ykman bio clear
    """
    dev = ctx.obj['dev']
    ctx.obj['controller'] = BioController(dev.driver)


@bio.command('dump-logs')
@click.pass_context
@click.argument('logfile', type=click.File('w'), metavar='LOGFILE')
def dump_logs(ctx, logfile):
    """
    Dump the stored logs to a file.

    \b
    LOGFILE File to write log data to. Use '-' to use stdout.
    """

    n_keys = len(list(get_descriptors()))
    if n_keys > 1:
        ctx.fail('Only one YubiKey can be connected to perform this action.')

    def prompt_re_insert_key():
        click.echo('Remove and re-insert your YubiKey to dump logs...')

        removed = False
        while True:
            sleep(0.1)
            n_keys = len(list(get_descriptors()))
            if not n_keys:
                removed = True
            if removed and n_keys == 1:
                return

    prompt_re_insert_key()

    dev = list(get_descriptors())[0].open_device(TRANSPORT.CCID)
    controller = BioController(dev.driver)

    sle_v = controller.read_sle_version()
    stm_v = controller.read_stm_version()
    logfile.write('# YubiKey BIO log dump\n')

    logfile.write('# {}\n'.format(sle_v))
    logfile.write(
        '# Session ID, Duration, SPI Dur., Command, Error, ' 'Enrollments, Flags\n'
    )
    for line in controller.dump_sle():
        logfile.write(
            '0x{:04x},0x{:04x},0x{:02x},0x{:02x},0x{:02x},0x{:02x},0x{:02x}\n'.format(
                *line
            )
        )

    logfile.write('# {}\n'.format(stm_v))
    logfile.write(
        '# Session ID, Duration, Command, Result, Last Enroll, '
        'Samples Remaining, Error, Vendor Error, Flags, Reserved\n'
    )
    for line in controller.dump_stm():
        logfile.write(
            '0x{:04x},0x{:04x},0x{:02x},0x{:02x},0x{:02x},0x{:02x},0x{:02x},0x{:02x},'
            '0x{:04x},0x{:08x}\n'.format(*line)
        )


@bio.command()
@click.pass_context
def clear(ctx):
    """
    Clear the logs from the device.
    WARNING: Do NOT do this without first saving the logs to a file.
    """
    if not click.confirm(
        'WARNING! This will delete all logs stored on the ' 'YubiKey. Proceed?',
        err=True,
    ):
        ctx.abort()

    controller = ctx.obj['controller']
    controller.clear_logs()
