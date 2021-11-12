# Copyright (c) 2021 Yubico AB
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


from .base import YkmanDevice
from .device import list_all_devices, scan_devices, get_name

from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.management import DeviceInfo

from time import sleep
from typing import Generator


"""
Various helpers intended to simplify scripting.

Add an import to your script:

  from ykman import scripting as s

Example usage:

  yubikey = s.single()
  print("Here is a YubiKey:", yubikey)


  print("Insert multiple YubiKeys")
  for yubikey in s.multi():
      print("You inserted {yubikey}")
  print("You pressed Ctrl+C, end of script")

"""


class ScriptingDevice:
    """Scripting-friendly proxy for YkmanDevice.

    This wrapper adds some helpful utility methods useful for scripting.
    """

    def __init__(self, wrapped, info):
        self._wrapped = wrapped
        self._info = info

    def __getattr__(self, attr):
        return getattr(self._wrapped, attr)

    def __str__(self):
        name = get_name(self._info, self.pid.get_type())
        serial = self._info.serial
        return f"{name} ({serial})" if serial else name

    @property
    def info(self) -> DeviceInfo:
        return self._info

    def otp(self) -> OtpConnection:
        return self.open_connection(OtpConnection)

    def ccid(self) -> SmartCardConnection:
        return self.open_connection(SmartCardConnection)

    def fido(self) -> FidoConnection:
        return self.open_connection(FidoConnection)


YkmanDevice.register(ScriptingDevice)


def single(*, prompt=True) -> ScriptingDevice:
    pids, state = scan_devices()
    n_devs = sum(pids.values())
    if prompt and n_devs == 0:
        print("Insert YubiKey...")
    while n_devs == 0:
        sleep(1.0)
        pids, new_state = scan_devices()
        n_devs = sum(pids.values())
    devs = list_all_devices()
    if len(devs) == 1:
        return ScriptingDevice(*devs[0])
    raise ValueError("Failed to get single YubiKey")


def multi(
    *, ignore_duplicates=True, allow_initial=False, prompt=True
) -> Generator[ScriptingDevice, None, None]:
    state = None
    handled_serials = set()  # Keep track of YubiKeys we've already handled.
    pids, _ = scan_devices()
    n_devs = sum(pids.values())
    if n_devs == 0:
        if prompt:
            print("Insert YubiKeys, one at a time...")
    elif not allow_initial:
        raise ValueError("YubiKeys must not be present initially.")

    while True:  # Run this until we stop the script with Ctrl+C
        pids, new_state = scan_devices()
        if new_state != state:
            state = new_state  # State has changed
            serials = set()
            for device, info in list_all_devices():
                serials.add(info.serial)
                if info.serial not in handled_serials:
                    handled_serials.add(info.serial)
                    yield ScriptingDevice(device, info)
            if not ignore_duplicates:  # Reset handled serials to currnently connected
                handled_serials = serials
        else:
            try:
                sleep(1.0)  # No change, sleep for 1 second.
            except KeyboardInterrupt:
                return  # Stop waiting
