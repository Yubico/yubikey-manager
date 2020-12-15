import unittest

from .framework import DestructiveYubikeyTestCase, exactly_one_yubikey_present
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from ykman.device import connect_to_device
from time import sleep


@unittest.skipIf(
    not exactly_one_yubikey_present(), "Exactly one YubiKey must be present."
)
class TestInterfaces(DestructiveYubikeyTestCase):
    def try_connection(self, conn_type):
        for _ in range(8):
            try:
                conn = connect_to_device(None, [conn_type])[0]
                conn.close()
                return
            except Exception:
                sleep(0.5)
        self.fail("Failed connecting to device over %s" % conn_type)

    def test_switch_interfaces(self):
        self.try_connection(FidoConnection)
        self.try_connection(OtpConnection)
        self.try_connection(FidoConnection)
        self.try_connection(SmartCardConnection)
        self.try_connection(OtpConnection)
        self.try_connection(SmartCardConnection)
        self.try_connection(OtpConnection)
        self.try_connection(FidoConnection)
        self.try_connection(SmartCardConnection)
        self.try_connection(FidoConnection)
        self.try_connection(SmartCardConnection)
        self.try_connection(OtpConnection)
