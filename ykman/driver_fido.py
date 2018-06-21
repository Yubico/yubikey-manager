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

from .driver import AbstractDriver, NotSupportedError
from .util import TRANSPORT, PID, YUBIKEY, Mode
from fido2.hid import CtapHidDevice, CTAPHID
from enum import IntEnum, unique
import logging
import struct


logger = logging.getLogger(__name__)


@unique
class CMD(IntEnum):
    YUBIKEY_DEVICE_CONFIG = CTAPHID.VENDOR_FIRST
    READ_CONFIG = CTAPHID.VENDOR_FIRST + 2
    WRITE_CONFIG = CTAPHID.VENDOR_FIRST + 3


@unique
class FIPS_U2F_CMD(IntEnum):
    ECHO = CTAPHID.VENDOR_FIRST
    WRITE_CONFIG = CTAPHID.VENDOR_FIRST + 1
    APP_VERSION = CTAPHID.VENDOR_FIRST + 2
    VERIFY_PIN = CTAPHID.VENDOR_FIRST + 3
    SET_PIN = CTAPHID.VENDOR_FIRST + 4
    RESET = CTAPHID.VENDOR_FIRST + 5
    VERIFY_FIPS_MODE = CTAPHID.VENDOR_FIRST + 6


class FidoDriver(AbstractDriver):

    transport = TRANSPORT.FIDO

    def __init__(self, dev):
        pid = PID(dev.descriptor['product_id'])
        super(FidoDriver, self).__init__(pid.get_type(), Mode.from_pid(pid))
        self._dev = dev

    def read_config(self):
        if self.key_type == YUBIKEY.NEO:
            raise NotSupportedError()
        if self.key_type == YUBIKEY.SKY:
            if self._dev.device_version < (4, 0, 0):  # Old SKY 1
                raise NotSupportedError()
        return self._dev.call(CMD.READ_CONFIG)

    def write_config(self, data):
        self._dev.call(CMD.WRITE_CONFIG, data)

    def read_version(self):
        version = self._dev.device_version
        if version[0] < 4:  # Before yK 4 this wasn't the fw version
            return None
        return version

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        data = struct.pack('BBH', mode_code, cr_timeout, autoeject_time)
        self._dev.call(CMD.YUBIKEY_DEVICE_CONFIG, data)


def descriptor_filter(desc):
    return desc['vendor_id'] == 0x1050 \
            and desc['usage_page'] == 0xf1d0 \
            and desc['usage'] == 1


def open_devices():
    for dev in CtapHidDevice.list_devices(descriptor_filter):
        try:
            yield FidoDriver(dev)
        except Exception as e:
            logger.debug('Failed opening FIDO device', exc_info=e)
