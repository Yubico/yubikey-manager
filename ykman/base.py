# Copyright (c) 2015-2020 Yubico AB
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

from yubikit.core import TRANSPORT, YubiKeyDevice
from yubikit.management import USB_INTERFACE
from enum import Enum, IntEnum, unique
from typing import Optional, Hashable


@unique
class YUBIKEY(Enum):
    """YubiKey hardware platforms."""

    YKS = "YubiKey Standard"
    NEO = "YubiKey NEO"
    SKY = "Security Key by Yubico"
    YKP = "YubiKey Plus"
    YK4 = "YubiKey 4"  # This includes YubiKey 5

    def get_pid(self, interfaces: USB_INTERFACE) -> "PID":
        suffix = "_".join(
            t.name for t in USB_INTERFACE if t in USB_INTERFACE(interfaces)
        )
        return PID[self.name + "_" + suffix]


@unique
class PID(IntEnum):
    """USB Product ID values for YubiKey devices."""

    YKS_OTP = 0x0010
    NEO_OTP = 0x0110
    NEO_OTP_CCID = 0x0111
    NEO_CCID = 0x0112
    NEO_FIDO = 0x0113
    NEO_OTP_FIDO = 0x0114
    NEO_FIDO_CCID = 0x0115
    NEO_OTP_FIDO_CCID = 0x0116
    SKY_FIDO = 0x0120
    YK4_OTP = 0x0401
    YK4_FIDO = 0x0402
    YK4_OTP_FIDO = 0x0403
    YK4_CCID = 0x0404
    YK4_OTP_CCID = 0x0405
    YK4_FIDO_CCID = 0x0406
    YK4_OTP_FIDO_CCID = 0x0407
    YKP_OTP_FIDO = 0x0410

    def get_type(self) -> YUBIKEY:
        return YUBIKEY[self.name.split("_", 1)[0]]

    def get_interfaces(self) -> USB_INTERFACE:
        return USB_INTERFACE(sum(USB_INTERFACE[x] for x in self.name.split("_")[1:]))


class YkmanDevice(YubiKeyDevice):
    """YubiKey device reference, with optional PID"""

    def __init__(self, transport: TRANSPORT, fingerprint: Hashable, pid: Optional[PID]):
        super(YkmanDevice, self).__init__(transport, fingerprint)
        self._pid = pid

    @property
    def pid(self) -> Optional[PID]:
        """Return the PID of the YubiKey, if available."""
        return self._pid

    def __repr__(self):
        return "%s(pid=%04x, fingerprint=%r)" % (
            type(self).__name__,
            self.pid or 0,
            self.fingerprint,
        )
