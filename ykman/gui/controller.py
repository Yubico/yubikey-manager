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

from __future__ import absolute_import, print_function
from usb.core import NoBackendError
from PySide import QtCore
from .util import SignalMap
from . import messages as m
from ..device import open_device, FailedOpeningDeviceException
from ..util import TRANSPORT, list_yubikeys


class Controller(QtCore.QObject):
    hasDeviceChanged = QtCore.Signal(bool)
    deviceNameChanged = QtCore.Signal(str)
    serialChanged = QtCore.Signal(int)
    versionChanged = QtCore.Signal(object)
    capabilitiesChanged = QtCore.Signal(int)
    enabledChanged = QtCore.Signal(int)
    canModeSwitchChanged = QtCore.Signal(bool)
    numberOfKeysChanged = QtCore.Signal(bool)

    def __init__(self, worker, parent=None):
        super(Controller, self).__init__(parent)

        self.worker = worker

        self._refreshing = False

        self._data = SignalMap()
        self._data.add_property('has_device', False, self.hasDeviceChanged)
        self._data.add_property('device_name', m.no_key, self.deviceNameChanged)
        self._data.add_property('serial', 0, self.serialChanged)
        self._data.add_property('version', None, self.versionChanged)
        self._data.add_property('capabilities', 0, self.capabilitiesChanged)
        self._data.add_property('enabled', 0, self.enabledChanged)
        self._data.add_property('can_mode_switch', False, self.canModeSwitchChanged)
        self._data.add_property('number_of_keys', 0, self.numberOfKeysChanged)

    @property
    def has_device(self):
        return self._data['has_device']

    @property
    def device_name(self):
        return self._data['device_name']

    @property
    def serial(self):
        return self._data['serial']

    @property
    def version(self):
        return self._data['version']

    @property
    def capabilities(self):
        return self._data['capabilities']

    @property
    def enabled(self):
        return self._data['enabled']

    @property
    def can_mode_switch(self):
        return self._data['can_mode_switch']

    @property
    def number_of_keys(self):
        return self._data['number_of_keys']

    def _grab_device(self, transports=sum(TRANSPORT)):
        if not self.has_device:
            raise ValueError('No device present')
        return open_device(transports)

    def _use_device(self, fn, cb=None, transports=sum(TRANSPORT)):
        def _func():
            dev = self._grab_device(transports)
            if dev is None:
                raise ValueError('Unable to access device!')
            return fn(dev)
        self.worker.post_bg(_func, cb, True)

    def refresh(self, can_skip=True):
        if can_skip and self._refreshing:
            return

        def _func():
            had_device = self.has_device

            try:
                yubikeys = list_yubikeys()
                n_keys = len(list_yubikeys())
            except NoBackendError:
                n_keys = 0
                print("No PyUSB backend detected!")

            if n_keys != self.number_of_keys:
                self.numberOfKeysChanged.emit(True)
            self._data['number_of_keys'] = n_keys
            if n_keys == 1:
                try:
                    dev = open_device()
                    if dev:
                        self._data['has_device'] = True
                        self._data['device_name'] = dev.device_name
                        self._data['serial'] = dev.serial
                        self._data['version'] = dev.version
                        self._data['capabilities'] = dev.capabilities
                        self._data['enabled'] = dev.enabled
                        self._data['can_mode_switch'] = dev.can_mode_switch
                    else:
                        self.hasDeviceChanged.emit(False)
                except FailedOpeningDeviceException as e:
                        print("Couldn't open device: {!s}".format(e))
                        self.hasDeviceChanged.emit(False)
            self._refreshing = False

        self._refreshing = True
        self.worker.post_bg(_func)

    def set_mode(self, mode, cb=None):
        def _func(dev):
            dev.mode = mode
        self._use_device(_func, cb)

    def read_slots(self, cb):
        self._use_device(lambda d: d.driver.slot_status, cb, TRANSPORT.OTP)

    def delete_slot(self, slot, cb):
        self._use_device(lambda d: d.driver.zap_slot(slot), cb, TRANSPORT.OTP)

    def swap_slots(self, cb):
        self._use_device(lambda d: d.driver.swap_slots(), cb, TRANSPORT.OTP)

    def program_otp(self, slot, key, fixed, uid, cb):
        self._use_device(lambda d: d.driver.program_otp(slot, key, fixed, uid),
                         cb, TRANSPORT.OTP)

    def program_static(self, slot, password, cb):
        self._use_device(lambda d: d.driver.program_static(slot, password), cb,
                         TRANSPORT.OTP)

    def program_hotp(self, slot, key, digits, cb):
        imf = 0
        hotp8 = (digits == 8)
        self._use_device(lambda d: d.driver.program_hotp(slot, key, imf, hotp8),
                         cb, TRANSPORT.OTP)

    def program_chalresp(self, slot, key, touch, cb):
        self._use_device(lambda d: d.driver.program_chalresp(slot, key, touch),
                         cb, TRANSPORT.OTP)
