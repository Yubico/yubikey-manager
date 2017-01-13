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


import six
from .util import CAPABILITY, TRANSPORT, parse_tlvs
from .driver import AbstractDriver
from binascii import b2a_hex


YK4_CAPA_TAG = 0x01
YK4_SERIAL_TAG = 0x02
YK4_ENABLED_TAG = 0x03


class FailedOpeningDeviceException(Exception):
    pass


_NULL_DRIVER = AbstractDriver()


class YubiKey(object):
    """
    YubiKey device handle
    """
    device_name = 'YubiKey'
    capabilities = 0
    enabled = 0
    _serial = None
    _can_mode_switch = True

    def __init__(self, descriptor, driver):
        if not driver:
            raise ValueError('No driver given!')
        self._descriptor = descriptor
        self._driver = driver
        self.device_name = descriptor.device_name

        if driver.transport == TRANSPORT.U2F and driver.sky:
            self.capabilities = CAPABILITY.U2F
            self._can_mode_switch = False
        elif self.version >= (4, 1, 0):
            if self.version == (4, 2, 4):  # 4.2.4 doesn't report correctly.
                capabilities = b'\x03\x01\x01\x3f'
            else:
                capabilities = driver.read_capabilities()
            self._parse_capabilities(capabilities)
            if self.capabilities == \
                    (CAPABILITY.OTP | CAPABILITY.CCID | CAPABILITY.U2F):
                self.device_name = 'YubiKey Edge'
                # YK Edge has no use for CCID.
                self.capabilities = CAPABILITY.OTP | CAPABILITY.U2F
        elif self.version >= (4, 0, 0):  # YK Plus
            self.capabilities = CAPABILITY.OTP | CAPABILITY.U2F
            self._can_mode_switch = False
        elif self.version >= (3, 0, 0):
            # NEO
            if driver.transport == TRANSPORT.CCID:
                self.capabilities = driver.probe_capabilities_support()
            else:
                # Assume base capabilities for NEO
                self.capabilities = CAPABILITY.OTP | CAPABILITY.CCID | \
                    CAPABILITY.OPGP | CAPABILITY.PIV | CAPABILITY.OATH
            if TRANSPORT.has(self.mode.transports, TRANSPORT.U2F) \
                    or self.version >= (3, 3, 0):
                    self.capabilities |= CAPABILITY.U2F
        else:  # Standard
            self.capabilities = CAPABILITY.OTP
            self._can_mode_switch = False
        if not self.enabled:
            # Assume everything supported is enabled, except USB transports
            self.enabled = self.capabilities & ~TRANSPORT.usb_transports()
            self.enabled |= self.mode.transports  # ...unless they are enabled.
        # If no CCID, disable dependent capabilities
        if not CAPABILITY.has(self.enabled, CAPABILITY.CCID):
            self.enabled = self.enabled & ~CAPABILITY.dependent_on_ccid()

    def _parse_capabilities(self, data):
        if not data:
            return
        c_len, data = six.indexbytes(data, 0), data[1:]
        data = data[:c_len]
        for tlv in parse_tlvs(data):
            if YK4_CAPA_TAG == tlv.tag:
                self.capabilities = int(b2a_hex(tlv.value), 16)
            elif YK4_SERIAL_TAG == tlv.tag:
                self._serial = int(b2a_hex(tlv.value), 16)
            elif YK4_ENABLED_TAG == tlv.tag:
                self.enabled = int(b2a_hex(tlv.value), 16)

    @property
    def version(self):
        return self._descriptor.version

    @property
    def serial(self):
        return self._serial or self._driver.serial

    @property
    def driver(self):
        return self._driver

    @property
    def transport(self):
        return self._driver.transport

    @property
    def mode(self):
        return self._descriptor.mode

    @mode.setter
    def mode(self, mode):
        if not self.has_mode(mode):
            raise ValueError('Mode not supported: %s' % mode)
        self.set_mode(mode)

    @property
    def can_mode_switch(self):
        return self._can_mode_switch

    def has_mode(self, mode):
        return self.mode == mode or \
            (self.can_mode_switch and
             TRANSPORT.has(self.capabilities, mode.transports))

    def set_mode(self, mode, cr_timeout=0, autoeject_time=None):
        flags = 0

        # If autoeject_time is set, then set the touch eject flag.
        if autoeject_time is not None:
            flags |= 0x80
        else:
            autoeject_time = 0

        # NEO < 3.3.1 (?) should always set 82 instead of 2.
        if self.version <= (3, 3, 1) and mode.code == 2:
            flags = 0x80
        self._driver.set_mode(flags | mode.code, cr_timeout, autoeject_time)

    def use_transport(self, transport):
        if self.transport == transport:
            return self
        if not TRANSPORT.has(self.mode.transports, transport):
            raise ValueError('%s transport not enabled!' % transport)
        my_mode = self.mode
        my_serial = self.serial

        del self._driver
        self._driver = _NULL_DRIVER

        dev = self._descriptor.open_device(transport)
        if dev.serial and my_serial:
            assert dev.serial == my_serial
        assert dev.mode == my_mode
        return dev

    def __str__(self):
        return '{0} {1[0]}.{1[1]}.{1[2]} {2} [{3.name}]' \
            'serial: {4} CAP: {5:x}' \
            .format(
                self.device_name,
                self.version,
                self.mode,
                self.transport,
                self.serial,
                self.capabilities
            )
