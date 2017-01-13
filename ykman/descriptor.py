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

from .util import TRANSPORT, Mode
from .device import YubiKey
from .driver_ccid import open_device as open_ccid
from .driver_u2f import open_device as open_u2f
from .driver_otp import open_device as open_otp
from .native.pyusb import get_usb_backend

import usb.core


YKS = 'YubiKey Standard'
NEO = 'YubiKey NEO'
SKY = 'FIDO U2F Security Key by Yubico'
YKP = 'YubiKey Plus'
YK4 = 'YubiKey 4'


_YUBIKEY_PIDS = {
    # YubiKey Standard
    0x0010: (YKS, TRANSPORT.OTP),

    # YubiKey NEO
    0x0110: (NEO, TRANSPORT.OTP),
    0x0111: (NEO, TRANSPORT.OTP | TRANSPORT.CCID),
    0x0112: (NEO, TRANSPORT.CCID),
    0x0113: (NEO, TRANSPORT.U2F),
    0x0114: (NEO, TRANSPORT.OTP | TRANSPORT.U2F),
    0x0115: (NEO, TRANSPORT.U2F | TRANSPORT.CCID),
    0x0116: (NEO, TRANSPORT.OTP | TRANSPORT.CCID | TRANSPORT.U2F),

    # FIDO U2F Security Key by Yubico
    0x0120: (SKY, TRANSPORT.U2F),

    # YubiKey 4
    0x0401: (YK4, TRANSPORT.OTP),
    0x0402: (YK4, TRANSPORT.U2F),
    0x0403: (YK4, TRANSPORT.OTP | TRANSPORT.U2F),
    0x0404: (YK4, TRANSPORT.CCID),
    0x0405: (YK4, TRANSPORT.OTP | TRANSPORT.CCID),
    0x0406: (YK4, TRANSPORT.U2F | TRANSPORT.CCID),
    0x0407: (YK4, TRANSPORT.OTP | TRANSPORT.CCID | TRANSPORT.U2F),

    # YubiKey Plus
    0x0410: (YKP, TRANSPORT.OTP | TRANSPORT.U2F),
}


class FailedOpeningDeviceException(Exception):
    pass


class Descriptor(object):
    _device_name = 'YubiKey'

    def __init__(self, usb_dev):
        v_int = usb_dev.bcdDevice
        self._version = ((v_int >> 8) % 16, (v_int >> 4) % 16, v_int % 16)
        name, transports = _YUBIKEY_PIDS[usb_dev.idProduct]
        self._mode = Mode(transports)
        self._device_name = name
        self.fingerprint = self._read_fingerprint(usb_dev)

    def _read_fingerprint(self, dev):
        return (
            dev.idProduct,
            dev.bcdDevice,
            dev.bus,
            dev.address,
            dev.iSerialNumber
        )

    @property
    def version(self):
        return self._version

    @property
    def mode(self):
        return self._mode

    @property
    def device_name(self):
        return self._device_name

    def open_device(self, transports=sum(TRANSPORT)):
        transports &= self.mode.transports
        dev = None
        try:
            if TRANSPORT.CCID & transports:
                dev = open_ccid()
            if TRANSPORT.OTP & transports and not dev:
                dev = open_otp()
            if TRANSPORT.U2F & transports and not dev:
                dev = open_u2f()
        except Exception as e:
            raise FailedOpeningDeviceException(e)

        return YubiKey(self, dev) if dev is not None else None


def get_descriptors():
    found = []  # Composite devices are listed multiple times on Windows...
    for dev in usb.core.find(True, idVendor=0x1050, backend=get_usb_backend()):
        if dev.idProduct in _YUBIKEY_PIDS:
            addr = (dev.bus, dev.address)
            if addr not in found:
                found.append(addr)
                yield Descriptor(dev)
