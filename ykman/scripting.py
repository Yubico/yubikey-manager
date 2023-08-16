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
from .device import list_all_devices, scan_devices
from .pcsc import list_devices as list_ccid

from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.management import DeviceInfo
from yubikit.support import get_name, read_info
from smartcard.Exceptions import NoCardException, CardConnectionException

from time import sleep
from typing import Generator, Optional, Set


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
        self._name = get_name(info, self.pid.yubikey_type if self.pid else None)

    def __getattr__(self, attr):
        return getattr(self._wrapped, attr)

    def __str__(self):
        serial = self._info.serial
        return f"{self._name} ({serial})" if serial else self._name

    @property
    def info(self) -> DeviceInfo:
        return self._info

    @property
    def name(self) -> str:
        return self._name

    def otp(self) -> OtpConnection:
        """Establish a OTP connection."""
        return self.open_connection(OtpConnection)

    def smart_card(self) -> SmartCardConnection:
        """Establish a Smart Card connection."""
        return self.open_connection(SmartCardConnection)

    def fido(self) -> FidoConnection:
        """Establish a FIDO connection."""
        return self.open_connection(FidoConnection)


YkmanDevice.register(ScriptingDevice)


def single(*, prompt=True) -> ScriptingDevice:
    """Connect to a YubiKey.

    :param prompt: When set, you will be prompted to
        insert a YubiKey.
    """
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
    *, ignore_duplicates: bool = True, allow_initial: bool = False, prompt: bool = True
) -> Generator[ScriptingDevice, None, None]:
    """Connect to multiple YubiKeys.


    :param ignore_duplicates: When set, duplicates are ignored.
    :param allow_initial: When set, YubiKeys can be connected
        at the start of the function call.
    :param prompt: When set, you will be prompted to
        insert a YubiKey.
    """
    state = None
    handled_serials: Set[Optional[int]] = set()
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
            if len(pids) == 0 and None in handled_serials:
                handled_serials.remove(None)  # Allow one key without serial at a time
            for device, info in list_all_devices():
                serials.add(info.serial)
                if info.serial not in handled_serials:
                    handled_serials.add(info.serial)
                    yield ScriptingDevice(device, info)
            if not ignore_duplicates:  # Reset handled serials to currently connected
                handled_serials = serials
        else:
            try:
                sleep(1.0)  # No change, sleep for 1 second.
            except KeyboardInterrupt:
                return  # Stop waiting


def _get_reader(reader) -> YkmanDevice:
    readers = [d for d in list_ccid(reader) if d.transport == TRANSPORT.NFC]
    if not readers:
        raise ValueError(f"No NFC reader found matching filter: '{reader}'")
    elif len(readers) > 1:
        names = [r.fingerprint for r in readers]
        raise ValueError(f"Multiple NFC readers matching filter: '{reader}' {names}")
    return readers[0]


def single_nfc(reader="", *, prompt=True) -> ScriptingDevice:
    """Connect to a YubiKey over NFC.

    :param reader: The name of the NFC reader.
    :param prompt: When set, you will prompted to place
        a YubiKey on NFC reader.
    """
    device = _get_reader(reader)
    while True:
        try:
            with device.open_connection(SmartCardConnection) as connection:
                info = read_info(connection)
            return ScriptingDevice(device, info)
        except NoCardException:
            if prompt:
                print("Place YubiKey on NFC reader...")
                prompt = False
            sleep(1.0)


def multi_nfc(
    reader="", *, ignore_duplicates=True, allow_initial=False, prompt=True
) -> Generator[ScriptingDevice, None, None]:
    """Connect to multiple YubiKeys over NFC.

    :param reader: The name of the NFC reader.
    :param ignore_duplicates: When set, duplicates are ignored.
    :param allow_initial: When set, YubiKeys can be connected
        at the start of the function call.
    :param prompt: When set, you will be prompted to place
        YubiKeys on the NFC reader.
    """
    device = _get_reader(reader)
    prompted = False

    try:
        with device.open_connection(SmartCardConnection) as connection:
            if not allow_initial:
                raise ValueError("YubiKey must not be present initially.")
    except NoCardException:
        if prompt:
            print("Place YubiKey on NFC reader...")
            prompted = True
        sleep(1.0)

    handled_serials: Set[Optional[int]] = set()
    current: Optional[int] = -1
    while True:  # Run this until we stop the script with Ctrl+C
        try:
            with device.open_connection(SmartCardConnection) as connection:
                info = read_info(connection)
            if info.serial in handled_serials or current == info.serial:
                if prompt and not prompted:
                    print("Remove YubiKey from NFC reader.")
                    prompted = True
            else:
                current = info.serial
                if ignore_duplicates:
                    handled_serials.add(current)
                yield ScriptingDevice(device, info)
                prompted = False
        except NoCardException:
            if None in handled_serials:
                handled_serials.remove(None)  # Allow one key without serial at a time
            current = -1
            if prompt and not prompted:
                print("Place YubiKey on NFC reader...")
                prompted = True
        except CardConnectionException:
            pass
        try:
            sleep(1.0)  # No change, sleep for 1 second.
        except KeyboardInterrupt:
            return  # Stop waiting
