from ykman.device import connect_to_device, list_all_devices, read_info
from ykman.pcsc import list_devices
from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import USB_INTERFACE
from functools import partial
from . import condition

import pytest
import time
import os


@pytest.fixture(scope="session")
def _device(pytestconfig):
    serial = pytestconfig.getoption("device")
    no_serial = pytestconfig.getoption("no_serial")
    if not serial:
        if no_serial:
            serial = None
        else:
            pytest.skip("No serial specified for device tests")
    reader = pytestconfig.getoption("reader")
    if reader:
        readers = list_devices(reader)
        if len(readers) != 1:
            pytest.exit("No/Multiple readers matched")
        dev = readers[0]
        with dev.open_connection(SmartCardConnection) as conn:
            info = read_info(None, conn)
    else:
        devices = list_all_devices()
        if len(devices) != 1:
            pytest.exit("Device tests require a single YubiKey")
        dev, info = devices[0]
    if info.serial != serial:
        pytest.exit("Device serial does not match: %d != %d" % (serial, info.serial))

    return dev, info


@pytest.fixture(scope="session")
def device(_device):
    return _device[0]


@pytest.fixture(scope="session")
def info(_device):
    return _device[1]


@pytest.fixture(scope="session")
def version(info):
    return info.version


@pytest.fixture(scope="session")
def transport(device):
    return device.transport


@pytest.fixture(scope="session")
def pid(device):
    return device.pid


@pytest.fixture(scope="session")
def await_reboot(transport):
    delay = float(os.environ.get("REBOOT_TIME", "2.0"))
    return partial(time.sleep, delay) if transport == TRANSPORT.USB else lambda: None


connection_scope = os.environ.get("CONNECTION_SCOPE", "function")


@pytest.fixture(scope=connection_scope)
@condition.transport(TRANSPORT.USB)
def otp_connection(device, info):
    if USB_INTERFACE.OTP in device.pid.get_interfaces():
        with connect_to_device(info.serial, [OtpConnection])[0] as c:
            yield c


@pytest.fixture(scope=connection_scope)
@condition.transport(TRANSPORT.USB)
def fido_connection(device, info):
    if USB_INTERFACE.FIDO in device.pid.get_interfaces():
        with connect_to_device(info.serial, [FidoConnection])[0] as c:
            yield c


@pytest.fixture(scope=connection_scope)
def ccid_connection(device, info):
    if device.transport == TRANSPORT.NFC:
        with device.open_connection(SmartCardConnection) as c:
            yield c
    elif USB_INTERFACE.CCID in device.pid.get_interfaces():
        with connect_to_device(info.serial, [SmartCardConnection])[0] as c:
            yield c
    else:
        pytest.skip("CCID connection not available")
