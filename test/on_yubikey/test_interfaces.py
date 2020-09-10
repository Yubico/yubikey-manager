import unittest

from .framework import DestructiveYubikeyTestCase, exactly_one_yubikey_present
from yubikit.core import TRANSPORT
from ykman.device import connect_to_device


@unittest.skipIf(
    not exactly_one_yubikey_present(), "Exactly one YubiKey must be present."
)
class TestInterfaces(DestructiveYubikeyTestCase):
    def test_switch_interfaces(self):
        connect_to_device(None, TRANSPORT.FIDO)
        connect_to_device(None, TRANSPORT.OTP)
        connect_to_device(None, TRANSPORT.FIDO)
        connect_to_device(None, TRANSPORT.CCID)
        connect_to_device(None, TRANSPORT.OTP)
        connect_to_device(None, TRANSPORT.CCID)
        connect_to_device(None, TRANSPORT.OTP)
        connect_to_device(None, TRANSPORT.FIDO)
        connect_to_device(None, TRANSPORT.CCID)
        connect_to_device(None, TRANSPORT.FIDO)
        connect_to_device(None, TRANSPORT.CCID)
        connect_to_device(None, TRANSPORT.OTP)
