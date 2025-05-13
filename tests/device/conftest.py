import os
import time
from functools import partial

import pytest

from ykman._cli.util import find_scp11_params
from ykman.device import list_all_devices, read_info
from ykman.pcsc import list_devices
from yubikit.core import TRANSPORT, _override_version
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.smartcard.scp import ScpKid
from yubikit.management import RELEASE_TYPE

from . import condition


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
            info = read_info(conn)
    else:
        devices = list_all_devices()
        if len(devices) != 1:
            pytest.exit("Device tests require a single YubiKey")
        dev, info = devices[0]
    if info.serial != serial:
        pytest.exit("Device serial does not match: %d != %r" % (serial, info.serial))

    if info.version_qualifier.type != RELEASE_TYPE.FINAL:
        _override_version(info.version)

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
    if device.supports_connection(OtpConnection):
        with device.open_connection(OtpConnection) as c:
            yield c


@pytest.fixture(scope=connection_scope)
@condition.transport(TRANSPORT.USB)
def fido_connection(device, info):
    if device.supports_connection(FidoConnection):
        with device.open_connection(FidoConnection) as c:
            yield c


@pytest.fixture(scope=connection_scope)
def ccid_connection(device, info):
    if device.supports_connection(SmartCardConnection):
        with device.open_connection(SmartCardConnection) as c:
            yield c
    else:
        pytest.skip("CCID connection not available")


@pytest.fixture(scope=connection_scope)
def scp_params(ccid_connection):
    try:
        return find_scp11_params(ccid_connection, ScpKid.SCP11b, 0)
    except ValueError:
        return None
