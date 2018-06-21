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

import time
from fido2.ctap2 import CTAP2, PinProtocolV1
from threading import Timer
from .driver_ccid import APDUError, SW_CONDITIONS_NOT_SATISFIED


class Fido2Controller(object):

    def __init__(self, driver):
        self.ctap = CTAP2(driver._dev)
        self.pin = PinProtocolV1(self.ctap)
        self._info = self.ctap.get_info()
        self._pin = self._info.options['clientPin']

    @property
    def has_pin(self):
        return self._pin

    def get_pin_retries(self):
        return self.pin.get_pin_retries()

    def set_pin(self, pin):
        self.pin.set_pin(pin)
        self._pin = True

    def change_pin(self, old_pin, new_pin):
        self.pin.change_pin(old_pin, new_pin)

    def reset(self, touch_callback=None):
        if (touch_callback):
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()
        try:
            self.ctap.reset()
            self._pin = False
        finally:
            if (touch_callback):
                touch_timer.cancel()

    @property
    def is_fips(self):
        return False


class FipsU2fController(object):

    def __init__(self, driver):
        self.driver = driver

    @property
    def has_pin(self):
        # We don't know, but the change and set commands are the same here.
        return True

    def set_pin(self, pin):
        raise NotImplementedError('Use the change_pin method instead.')

    def change_pin(self, old_pin, new_pin):
        return self.driver.fips_change_pin(old_pin, new_pin)

    def reset(self, touch_callback=None):
        if (touch_callback):
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        try:
            while True:
                try:
                    self.driver.fips_reset()
                    self._pin = False
                    return True
                except APDUError as e:
                    if e.sw == SW_CONDITIONS_NOT_SATISFIED:
                        time.sleep(0.5)
                    else:
                        raise e

        finally:
            if (touch_callback):
                touch_timer.cancel()

    @property
    def is_fips(self):
        return True

    @property
    def is_in_fips_mode(self):
        return self.driver.is_in_fips_mode
