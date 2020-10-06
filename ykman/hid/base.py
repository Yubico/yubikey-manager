from __future__ import absolute_import

from yubikit.core import YubiKeyDevice, PID
from yubikit.core.otp import OtpConnection

YUBICO_VID = 0x1050

USAGE_FIDO = (0xF1D0, 1)
USAGE_OTP = (1, 6)


class OtpYubiKeyDevice(YubiKeyDevice):
    """YubiKey USB HID OTP device"""

    def __init__(self, path, pid, connection_cls):
        super(OtpYubiKeyDevice, self).__init__(path, PID(pid))
        self.path = path
        self._connection_cls = connection_cls

    def open_otp_connection(self) -> OtpConnection:
        """Open an OTP connection"""
        return self._connection_cls(self.path)
