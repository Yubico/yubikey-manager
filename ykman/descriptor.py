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

from .util import PID, TRANSPORT, Mode
from .device import YubiKey
from .driver_ccid import open_devices as open_ccid
from .driver_fido import open_devices as open_fido
from .driver_otp import open_devices as open_otp
from .native.pyusb import get_usb_backend

import logging
import usb.core
import time

logger = logging.getLogger(__name__)


class FailedOpeningDeviceException(Exception):
    pass


class Descriptor(object):

    def __init__(self, key_type, mode, version, fingerprint, serial=None):
        self._logger = logger.getChild('Descriptor')
        self._version = version
        self._key_type = key_type
        self._mode = mode
        self._fingerprint = fingerprint

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def version(self):
        return self._version

    @property
    def mode(self):
        return self._mode

    @property
    def key_type(self):
        return self._key_type

    def open_device(self, transports=sum(TRANSPORT), serial=None, attempts=10):
        self._logger.debug('transports: 0x%x, self.mode.transports: 0x%x',
                           transports, self.mode.transports)

        transports &= self.mode.transports

        logger.debug('Opening driver for serial: %s, type: %s, mode: %s',
                     serial, self.key_type, self.mode)
        for attempt in range(1, attempts + 1):
            logger.debug('Attempt %d of %d', attempt, attempts)
            sleep_time = attempt * 0.1
            for drv in _list_drivers(transports):
                logger.debug('Found driver: %s, key_type: %s, mode: %s',
                             drv, drv.key_type, drv.mode)
                dev = YubiKey(self, drv)
                if serial is not None and dev.serial != serial:
                    logger.debug('Serial does not match. Want: %s, got: %s',
                                 serial, dev.serial)
                    del dev
                    continue
                if (drv.key_type, drv.mode) != (self.key_type, self.mode):
                    logger.debug('Descriptor mismatch. Want: %s, got: %s',
                                 (self.key_type, self.mode),
                                 (drv.key_type, drv.mode))
                    del dev
                    continue
                return dev
            #  Wait a little before trying again.
            logger.debug('Sleeping for %f s', sleep_time)
            time.sleep(sleep_time)
        logger.debug('No matching device found')
        raise FailedOpeningDeviceException()

    @classmethod
    def from_usb(cls, usb_dev):
        v_int = usb_dev.bcdDevice
        version = ((v_int >> 8) % 16, (v_int >> 4) % 16, v_int % 16)
        pid = PID(usb_dev.idProduct)
        fp = (pid, version, usb_dev.bus, usb_dev.address, usb_dev.iSerialNumber)
        return cls(pid.get_type(), Mode.from_pid(pid), version, fp)

    @classmethod
    def from_driver(cls, driver):
        fp = (driver.key_type, driver.mode)
        return cls(driver.key_type, driver.mode, None, fp)


def _gen_descriptors():
    found = []  # Composite devices are listed multiple times on Windows...
    for dev in usb.core.find(True, idVendor=0x1050, backend=get_usb_backend()):
        try:
            addr = (dev.bus, dev.address)
            if addr not in found:
                found.append(addr)
                yield Descriptor.from_usb(dev)
        except ValueError as e:
            logger.debug('Invalid PID', exc_info=e)


def get_descriptors():
    return list(_gen_descriptors())


def _list_drivers(transports):
    if TRANSPORT.CCID & transports:
        for dev in open_ccid():
            if dev:
                yield dev
    if TRANSPORT.OTP & transports:
        for dev in open_otp():
            if dev:
                yield dev
    if TRANSPORT.FIDO & transports:
        for dev in open_fido():
            if dev:
                yield dev


def list_devices(transports=sum(TRANSPORT)):
    for d in _list_drivers(transports):
        yield YubiKey(Descriptor.from_driver(d), d)


def _open_driver(transports, serial, key_type, mode, attempts):
    logger.debug('Opening driver for transports: %s, serial: %s, key_type: %s, '
                 'mode: %s',
                 transports, serial, key_type, mode)
    for attempt in range(1, attempts + 1):
        logger.debug('Attempt %d of %d', attempt, attempts)
        sleep_time = attempt * 0.1
        for dev in list_devices(transports):
            logger.debug('Found driver: %s serial: %s, key_type: %s, mode: %s',
                         dev.driver, dev.serial, dev.driver.key_type,
                         dev.driver.mode)
            if serial is not None and dev.serial != serial:
                logger.debug('Serial does not match. Want: %s, got: %s',
                             serial, dev.serial)
                del dev
                continue
            if key_type is not None and dev.driver.key_type != key_type:
                logger.debug('Key type does not match. Want: %s, got: %s',
                             key_type, dev.driver.key_type)
                del dev
                continue
            return dev.driver
            if mode is not None and dev.driver.mode != mode:
                logger.debug('Mode does not match. Want: %s, got: %s',
                             mode, dev.driver.mode)
                del dev
                continue
        #  Wait a little before trying again.
        logger.debug('Sleeping for %f s', sleep_time)
        time.sleep(sleep_time)
        logger.debug('No driver found for serial: %s, key_type: %s, mode: %s',
                     serial, key_type, mode)
    raise FailedOpeningDeviceException()


def open_device(transports=sum(TRANSPORT), serial=None, key_type=None,
                mode=None, attempts=10):
    driver = _open_driver(transports, serial, key_type, mode, attempts)
    matches = [d for d in get_descriptors() if (d.key_type, d.mode)
               == (driver.key_type, driver.mode)]
    if len(matches) == 1:  # Only one matching descriptor, must be it
        descriptor = matches[0]
    else:
        descriptor = Descriptor.from_driver(driver)
    return YubiKey(descriptor, driver)
