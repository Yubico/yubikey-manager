# Copyright (c) 2020 Yubico AB
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

from ..base import YkmanDevice, PID
from .base import OtpYubiKeyDevice
from yubikit.core import TRANSPORT
from fido2.hid import list_descriptors, open_connection, CtapHidDevice
from typing import List, Callable
import sys
import logging

logger = logging.getLogger(__name__)


if sys.platform.startswith("linux"):
    from . import linux as backend
elif sys.platform.startswith("win32"):
    from . import windows as backend
elif sys.platform.startswith("darwin"):
    from . import macos as backend
else:
    raise Exception("Unsupported platform")


list_otp_devices: Callable[[], List[OtpYubiKeyDevice]] = backend.list_devices


class CtapYubiKeyDevice(YkmanDevice):
    """YubiKey FIDO USB HID device"""

    def __init__(self, descriptor):
        super(CtapYubiKeyDevice, self).__init__(
            TRANSPORT.USB, descriptor.path, PID(descriptor.pid)
        )
        self.descriptor = descriptor

    def supports_connection(self, connection_type):
        return issubclass(CtapHidDevice, connection_type)

    def open_connection(self, connection_type):
        if self.supports_connection(connection_type):
            return CtapHidDevice(self.descriptor, open_connection(self.descriptor))
        return super(OtpYubiKeyDevice, self).open_connection(connection_type)


def list_ctap_devices() -> List[CtapYubiKeyDevice]:
    devs = []
    for desc in list_descriptors():
        if desc.vid == 0x1050:
            try:
                devs.append(CtapYubiKeyDevice(desc))
            except ValueError:
                logger.debug(f"Unsupported Yubico device with PID: {desc.pid:02x}")
    return devs
