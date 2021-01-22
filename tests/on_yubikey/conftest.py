from ykman.device import connect_to_device, list_all_devices
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection

import pytest
import os


@pytest.fixture(scope="session")
def _pid_info():
    devices = list_all_devices()
    if len(devices) != 1:
        pytest.skip("Device tests require a single YubiKey to be attached")
    dev, info = devices[0]
    assert info.serial == int(os.environ.get("DESTRUCTIVE_TEST_YUBIKEY_SERIALS"))
    return dev.pid, info


@pytest.fixture(scope="session")
def pid(_pid_info):
    return _pid_info[0]


@pytest.fixture(scope="session")
def info(_pid_info):
    return _pid_info[1]


@pytest.fixture(scope="session")
def key_type(pid):
    return pid.get_type()


connection_scope = os.environ.get("CONNECTION_SCOPE", "module")


@pytest.fixture(scope=connection_scope)
def otp_connection(info):
    with connect_to_device(info.serial, [OtpConnection])[0] as c:
        yield c


@pytest.fixture(scope=connection_scope)
def fido_connection(info):
    with connect_to_device(info.serial, [FidoConnection])[0] as c:
        yield c


@pytest.fixture(scope=connection_scope)
def ccid_connection(info):
    with connect_to_device(info.serial, [SmartCardConnection])[0] as c:
        yield c
