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

from .driver import AbstractDriver
from .util import TRANSPORT, YUBIKEY, PID
from fido2.hid import CtapHidDevice, CTAPHID
import logging
import struct


logger = logging.getLogger(__name__)


YUBIKEY_DEVICE_CONFIG = CTAPHID.VENDOR_FIRST
YK4_CAPABILITIES = CTAPHID.VENDOR_FIRST + 2


class U2FDriver(AbstractDriver):

    transport = TRANSPORT.FIDO

    def __init__(self, dev):
        super(U2FDriver, self).__init__(PID(dev.descriptor['product_id']))
        self._dev = dev

    def read_config(self):
        return self._dev.call(YK4_CAPABILITIES, b'\x00')

    def guess_version(self):
        if self.key_type == YUBIKEY.NEO:  # Applet version
            return (3, 2, 0)
        return self._dev.device_version

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        data = struct.pack('BBH', mode_code, cr_timeout, autoeject_time)
        self._dev.call(YUBIKEY_DEVICE_CONFIG, data)


def descriptor_filter(desc):
    return desc['vendor_id'] == 0x1050 \
            and desc['usage_page'] == 0xf1d0 \
            and desc['usage'] == 1


def open_devices():
    for dev in CtapHidDevice.list_devices(descriptor_filter):
        try:
            yield U2FDriver(dev)
        except Exception as e:
            logger.debug('Failed opening FIDO device', exc_info=e)
