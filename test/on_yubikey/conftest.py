from __future__ import print_function
import functools
import pytest
import test.util
import ykman.descriptor

from ykman.util import TRANSPORT
from .framework import _test_serials


@pytest.fixture(params=[s for s in _test_serials or []])
def ykman_cli(request):
    serial = request.param

    with ykman.descriptor.open_device(serial=serial) as dev:
        if _device_satisfies_test_conditions(dev, request.function):
            return functools.partial(test.util.ykman_cli, '--device', serial)
        else:
            pytest.skip('Test not applicable to this YubiKey')


def open_device(request, serial, transport):
    with ykman.descriptor.open_device(transports=transport, serial=serial) as dev:  # noqa: E501
        if _device_satisfies_test_conditions(dev, request.function):
            return functools.partial(
                ykman.descriptor.open_device,
                transports=transport,
                serial=serial
            )
        else:
            pytest.skip('Test not applicable to this YubiKey')


@pytest.fixture(params=[s for s in _test_serials or []])
def open_device_ccid(request):
    return open_device(request, request.param, TRANSPORT.CCID)


@pytest.fixture(params=[s for s in _test_serials or []])
def open_device_fido(request):
    return open_device(request, request.param, TRANSPORT.FIDO)


@pytest.fixture(params=[s for s in _test_serials or []])
def open_device_otp(request):
    return open_device(request, request.param, TRANSPORT.OTP)


def _device_satisfies_test_conditions(dev, test_method):
    if '_yubikey_conditions' in dir(test_method):
        conditions = getattr(test_method, '_yubikey_conditions')
        return all(cond(dev) for cond in conditions)
    else:
        return True
