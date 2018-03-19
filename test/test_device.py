import unittest
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

from ykman.device import YubiKey
from ykman.util import TRANSPORT


class TestSpecificError(Exception):
    pass


def make_mocks():
    descriptor = Mock()
    descriptor.version = (4, 0, 0)
    descriptor.mode.transports = TRANSPORT.CCID
    driver = Mock()
    return descriptor, driver


class TestDevice(unittest.TestCase):

    def test_with_as_closes_driver(self):
        descriptor, driver = make_mocks()
        with YubiKey(descriptor, driver) as dev:  # noqa: F841
            pass
        driver.close.assert_called_once_with()

    def test_with_as_reraises_exception(self):
        descriptor, driver = make_mocks()

        with self.assertRaises(TestSpecificError):
            with YubiKey(descriptor, driver) as dev:  # noqa: F841
                raise TestSpecificError()

        driver.close.assert_called_once_with()

    def test_with_closes_driver(self):
        descriptor, driver = make_mocks()
        with YubiKey(descriptor, driver):
            pass
        driver.close.assert_called_once_with()

    def test_with_reraises_exception(self):
        descriptor, driver = make_mocks()

        with self.assertRaises(TestSpecificError):
            with YubiKey(descriptor, driver):
                raise TestSpecificError()

        driver.close.assert_called_once_with()
