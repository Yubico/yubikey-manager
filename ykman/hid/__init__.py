from __future__ import absolute_import

from .base import OtpYubiKeyDevice
from yubikit.core import YubiKeyDevice, PID
from fido2.hid import list_descriptors, open_connection, CtapHidDevice
from typing import List, Callable
import sys


if sys.platform.startswith("linux"):
    from . import linux as backend
elif sys.platform.startswith("win32"):
    from . import windows as backend
elif sys.platform.startswith("darwin"):
    from . import macos as backend
else:
    raise Exception("Unsupported platform")


list_otp_devices: Callable[[], List[OtpYubiKeyDevice]] = backend.list_devices


class CtapYubiKeyDevice(YubiKeyDevice):
    """YubiKey FIDO USB HID device"""

    def __init__(self, descriptor):
        super(CtapYubiKeyDevice, self).__init__(descriptor.path, PID(descriptor.pid))
        self.descriptor = descriptor

    def open_ctap_connection(self) -> CtapHidDevice:
        return CtapHidDevice(self.descriptor, open_connection(self.descriptor))


def list_ctap_devices() -> List[CtapYubiKeyDevice]:
    return [CtapYubiKeyDevice(d) for d in list_descriptors()]
