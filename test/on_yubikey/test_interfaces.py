import unittest

from .framework import DestructiveYubikeyTestCase, exactly_one_yubikey_present
from ykman import driver_fido, driver_otp, driver_ccid


@unittest.skipIf(not exactly_one_yubikey_present(),
                 'Exactly one YubiKey must be present.')
class TestInterfaces(DestructiveYubikeyTestCase):

    def test_switch_interfaces(self):
        next(driver_fido.open_devices()).read_config()
        next(driver_otp.open_devices()).read_config()
        next(driver_fido.open_devices()).read_config()
        next(driver_ccid.open_devices()).read_config()
        next(driver_otp.open_devices()).read_config()
        next(driver_ccid.open_devices()).read_config()
        next(driver_otp.open_devices()).read_config()
        next(driver_fido.open_devices()).read_config()
        next(driver_ccid.open_devices()).read_config()
        next(driver_fido.open_devices()).read_config()
        next(driver_ccid.open_devices()).read_config()
        next(driver_otp.open_devices()).read_config()
