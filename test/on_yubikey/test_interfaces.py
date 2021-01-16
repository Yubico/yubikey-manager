import unittest

from .framework import DestructiveYubikeyTestCase, exactly_one_yubikey_present
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from ykman.base import YUBIKEY
from ykman.device import connect_to_device
from time import sleep


@unittest.skipIf(
    not exactly_one_yubikey_present(), "Exactly one YubiKey must be present."
)
class TestInterfaces(DestructiveYubikeyTestCase):
    def try_connection(self, conn_type):
        if self.key_type == YUBIKEY.NEO and conn_type == SmartCardConnection:
            sleep(3.5)
        conn, dev, info = connect_to_device(None, [conn_type])
        conn.close()

    def setUp(self):
        conn, dev, info = connect_to_device()
        conn.close()
        self.key_type = dev.pid.get_type()

    def test_switch_interfaces(self):
        self.try_connection(FidoConnection)
        self.try_connection(OtpConnection)
        self.try_connection(FidoConnection)
        self.try_connection(SmartCardConnection)
        self.try_connection(OtpConnection)
        self.try_connection(SmartCardConnection)
        self.try_connection(FidoConnection)
