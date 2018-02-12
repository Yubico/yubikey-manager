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
from .driver_u2f import open_devices as open_u2f
from .driver_otp import open_devices as open_otp
from .native.pyusb import get_usb_backend

import logging
import usb.core
import time

logger = logging.getLogger(__name__)


class FailedOpeningDeviceException(Exception):
    pass


class Descriptor(object):

    def __init__(self, pid, version, certain, fingerprint, serial=None):
        self._logger = logger.getChild('Descriptor')
        self._version = version
        self._certain = certain
        self._pid = pid
        self._serial = serial
        self._key_type = pid.get_type()
        self._mode = Mode.from_pid(pid)
        self._fingerprint = fingerprint

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def version(self):
        return self._version

    @property
    def version_certain(self):
        return self._certain

    @property
    def pid(self):
        return self._pid

    @property
    def mode(self):
        return self._mode

    @property
    def key_type(self):
        return self._key_type

    def open_device(self, transports=sum(TRANSPORT), attempts=10):
        self._logger.debug('transports: 0x%x, self.mode.transports: 0x%x',
                           transports, self.mode.transports)

        transports &= self.mode.transports
        driver = open_driver(transports, self._serial, self._pid, attempts)
        if self._serial is None:
            self._serial = driver.serial
        return YubiKey(self, driver)

    @classmethod
    def from_usb(cls, usb_dev):
        v_int = usb_dev.bcdDevice
        version = ((v_int >> 8) % 16, (v_int >> 4) % 16, v_int % 16)
        pid = PID(usb_dev.idProduct)
        fp = (pid, version, usb_dev.bus, usb_dev.address, usb_dev.iSerialNumber)
        return cls(pid, version, True, fp)

    @classmethod
    def from_driver(cls, driver):
        version, certain = driver.guess_version()
        fp = (driver.pid, version, driver.serial)
        return cls(driver.pid, version, certain, fp, driver.serial)


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


def list_drivers(transports=sum(TRANSPORT)):
    if TRANSPORT.CCID & transports:
        for dev in open_ccid():
            if dev:
                yield dev
    if TRANSPORT.OTP & transports:
        for dev in open_otp():
            if dev:
                yield dev
    if TRANSPORT.U2F & transports:
        for dev in open_u2f():
            if dev:
                yield dev


def open_driver(transports=sum(TRANSPORT), serial=None, pid=None, attempts=10):
    logger.debug('Opening driver for serial: %s, pid: %s', serial, pid)
    for attempt in range(1, attempts + 1):
        logger.debug('Attempt %d of %d', attempt, attempts)
        sleep_time = attempt * 0.1
        for drv in list_drivers(transports):
            if drv is not None:
                logger.debug('Found driver: %s serial: %s, pid: %s',
                             drv, drv.serial, drv.pid)
                if serial is not None and drv.serial != serial:
                    logger.debug('Serial does not match. Want: %s, got: %s',
                                 serial, drv.serial)
                    del drv
                    continue
                if pid is not None and drv.pid != pid:
                    logger.debug('PID does not match. Want: %s, got: %s',
                                 pid, drv.pid)
                    del drv
                    continue
                return drv
        #  Wait a little before trying again.
        logger.debug('Sleeping for %f s', sleep_time)
        time.sleep(sleep_time)
    logger.debug('No driver found for serial: %s, pid: %s', serial, pid)
    raise FailedOpeningDeviceException()


def open_device(transports=sum(TRANSPORT), serial=None, pid=None, attempts=10):
    driver = open_driver(transports, serial, pid, attempts)
    matches = [d for d in get_descriptors() if d.pid == driver.pid]
    if len(matches) == 1:  # Only one matching descriptor, must be it
        descriptor = matches[0]
    else:
        descriptor = Descriptor.from_driver(driver)
    return YubiKey(descriptor, driver)
