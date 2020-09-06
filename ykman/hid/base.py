from __future__ import absolute_import

from yubikit.core import YubiKeyDevice, PID
from fido2.hid import CtapHidDevice as _CtapHidDevice

YUBICO_VID = 0x1050

USAGE_FIDO = (0xF1D0, 1)
USAGE_OTP = (1, 6)


class CtapHidDevice(_CtapHidDevice):
    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()

    @classmethod
    def open_path(cls, path):
        devs = list(cls.list_devices(lambda d: d["path"].rstrip(b"\0") == path))
        if len(devs) != 1:
            raise Exception("Device not found")
        return devs[0]


class HidDevice(YubiKeyDevice):
    """YubiKey USB HID device"""

    def __init__(self, fingerprint, pid, open_otp=None, open_ctap=None):
        super(HidDevice, self).__init__(fingerprint)
        self.pid = PID(pid)
        self.open_otp = open_otp
        self.open_ctap = open_ctap

    @property
    def has_otp(self):
        return self.open_otp is not None

    def open_otp_connection(self):
        """Open an OTP connection"""
        return self.open_otp()

    @property
    def has_ctap(self):
        return self.open_ctap is not None

    def open_ctap_device(self):
        """Open a python-fido2 CtapDevice"""
        return self.open_ctap()
