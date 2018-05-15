from .util import DestructiveYubikeyTestCase
from ykman import driver_fido, driver_otp, driver_ccid


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
