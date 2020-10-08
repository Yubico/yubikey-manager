import unittest

from .framework import DestructiveYubikeyTestCase, exactly_one_yubikey_present
from yubikit.core import USB_INTERFACE
from ykman.device import connect_to_device
from time import sleep


@unittest.skipIf(
    not exactly_one_yubikey_present(), "Exactly one YubiKey must be present."
)
class TestInterfaces(DestructiveYubikeyTestCase):
    def try_connection(self, interface):
        for _ in range(8):
            try:
                conn = connect_to_device(None, interface)[0]
                conn.close()
                return
            except Exception:
                sleep(0.5)
        self.fail("Failed connecting to device over " + interface.name)

    def test_switch_interfaces(self):
        self.try_connection(USB_INTERFACE.FIDO)
        self.try_connection(USB_INTERFACE.OTP)
        self.try_connection(USB_INTERFACE.FIDO)
        self.try_connection(USB_INTERFACE.CCID)
        self.try_connection(USB_INTERFACE.OTP)
        self.try_connection(USB_INTERFACE.CCID)
        self.try_connection(USB_INTERFACE.OTP)
        self.try_connection(USB_INTERFACE.FIDO)
        self.try_connection(USB_INTERFACE.CCID)
        self.try_connection(USB_INTERFACE.FIDO)
        self.try_connection(USB_INTERFACE.CCID)
        self.try_connection(USB_INTERFACE.OTP)
