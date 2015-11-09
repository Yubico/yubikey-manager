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


from .util import CAPABILITY, parse_tlv_list
from .driver_ccid import open_device as open_ccid
from .driver_u2f import open_device as open_u2f
from .driver_otp import open_device as open_otp


YK4_CAPA_TAG = 0x01
YK4_SERIAL_TAG = 0x02
YK4_ENABLED_TAG = 0x03


class YubiKey(object):
    """
    YubiKey device handle
    """
    device_name = 'YubiKey'
    capabilities = 0
    enabled = 0

    def __init__(self, driver):
        if not driver:
            raise ValueError('No driver given!')
        self._driver = driver

        if driver.transport == 'U2F' and driver.sky:
            self.device_name = 'Security Key by Yubico'
            self.capabilities = CAPABILITY.U2F
        elif self.version >= (4, 1, 0):
            self.device_name = 'YubiKey 4'
            self._parse_capabilities(driver.read_capabilities())
            if self.capabilities == 0x07:  # YK Edge has no use for CCID.
                self.device_name = 'YubiKey Edge'
                self.capabilities = CAPABILITY.OTP | CAPABILITY.U2F
        elif self.version >= (4, 0, 0):  # YK Plus
            self.device_name = 'YubiKey Plus'
            self.capabilities = CAPABILITY.OTP | CAPABILITY.U2F
        elif self.version >= (3, 0, 0):
            self.device_name = 'YubiKey NEO'
            if driver.transport == 'CCID':
                self.capabilities = driver.probe_capabilities_support()
            elif self.mode.u2f or self.version >= (3, 3, 0):
                self.capabilities = CAPABILITY.OTP | CAPABILITY.U2F \
                    | CAPABILITY.CCID
            else:
                self.capabilities = CAPABILITY.OTP | CAPABILITY.CCID
        else:
            self.capabilities = CAPABILITY.OTP

        if not self.enabled:  # Assume everything supported is enabled.
            self.enabled = self.capabilities
            # TODO: Remove transports based on mode.

    def _parse_capabilities(self, data):
        if not data:
            return
        c_len, data = ord(data[0]), data[1:]
        data = data[:c_len]
        data = parse_tlv_list(data)
        if YK4_CAPA_TAG in data:
            self.capabilities = int(data[YK4_CAPA_TAG].encode('hex'), 16)
        if YK4_SERIAL_TAG in data:
            self.serial = int(data[YK4_SERIAL_TAG].encode('hex'), 16)
        if YK4_ENABLED_TAG in data:
            self.enabled = int(data[YK4_ENABLED_TAG].encode('hex'), 16)
        else:
            self.enabled = self.capabilities

    @property
    def version(self):
        return self._driver.version

    @property
    def serial(self):
        return self._driver.serial

    @property
    def mode(self):
        return self._driver.mode

    @mode.setter
    def mode(self, mode):
        # TODO: Check if mode is supported.
        # TODO: Set TOUCH_EJECT bit if needed.
        self._driver.set_mode(mode.code)
        self._driver._mode = mode

    def __str__(self):
        return '{0} {1[0]}.{1[1]}.{1[2]} {2} [{3}] serial: {4} CAP: {5:x}' \
            .format(
                self.device_name,
                self.version,
                self.mode,
                self._driver.transport,
                self.serial,
                self.capabilities
            )


def open_device(otp=True, u2f=True, ccid=True):
    dev = None
    if ccid:
        dev = open_ccid()
    if otp and not dev:
        dev = open_otp()
    if u2f and not dev:
        dev = open_u2f()

    return YubiKey(dev)
