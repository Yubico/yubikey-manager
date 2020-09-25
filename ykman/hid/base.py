from __future__ import absolute_import

from yubikit.core import YubiKeyDevice, PID
from fido2.hid import open_connection, CtapHidDevice

YUBICO_VID = 0x1050

USAGE_FIDO = (0xF1D0, 1)
USAGE_OTP = (1, 6)


class CtapHidConnection(CtapHidDevice):
    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()


class CtapYubiKeyDevice(YubiKeyDevice):
    """YubiKey FIDO USB HID device"""

    def __init__(self, descriptor):
        super(CtapYubiKeyDevice, self).__init__(descriptor.path)
        self.descriptor = descriptor
        self.pid = PID(descriptor.pid)

    def open_ctap_connection(self):
        return CtapHidConnection(self.descriptor, open_connection(self.descriptor))


class OtpYubiKeyDevice(YubiKeyDevice):
    """YubiKey USB HID OTP device"""

    def __init__(self, path, pid, connection_cls):
        super(OtpYubiKeyDevice, self).__init__(path)
        self.path = path
        self.pid = PID(pid)
        self.connection_cls = connection_cls

    def open_otp_connection(self):
        """Open an OTP connection"""
        return self.connection_cls(self.path)
