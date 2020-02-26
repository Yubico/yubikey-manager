from __future__ import print_function
import functools
import pytest
import test.util
import time
import ykman.descriptor

from ykman.util import TRANSPORT
from .framework import _test_serials


def partial_with_retry(
        func,
        *partial_args,
        **partial_kwargs
):
    '''
    Like functools.partial, but adds a `retry_count` parameter to the wrapped
    function.

    If the wrapped function raises a non-exit exception or an `OSError`, then
    the returned function waits for 0.5 seconds and then retries the wrapped
    function call with the same arguments. This is done no more than
    `retry_count` times, after which the exception is re-raised.

    The `retry_count` argument is not passed to the wrapped function.
    '''

    default_retry_count = partial_kwargs.pop('default_retry_count', 0)

    @functools.wraps(func)
    def wrap_func(*args, **kwargs):
        retry_count = kwargs.pop('retry_count', default_retry_count)
        for k, v in partial_kwargs.items():
            kwargs.setdefault(k, v)
        try:
            return func(*(partial_args + args), **kwargs)
        except Exception or OSError:
            if retry_count > 0:
                time.sleep(0.5)
                return wrap_func(*args, retry_count=retry_count-1, **kwargs)
            raise
    return wrap_func


@pytest.fixture(params=[s for s in _test_serials or []])
def ykman_cli(request):
    serial = request.param

    with ykman.descriptor.open_device(serial=serial) as dev:
        if _device_satisfies_test_conditions(dev, request.function):
            f = partial_with_retry(
                test.util.ykman_cli,
                '--device', dev.serial,
                default_retry_count=1
            )
            f.with_bytes_output = partial_with_retry(
                test.util.ykman_cli_bytes,
                '--device', dev.serial,
                default_retry_count=1)
            return f
        else:
            pytest.skip('Test not applicable to this YubiKey')


def open_device(request, serial, transport):
    with ykman.descriptor.open_device(transports=transport, serial=serial) as dev:  # noqa: E501
        if _device_satisfies_test_conditions(dev, request.function):
            return partial_with_retry(
                ykman.descriptor.open_device,
                transports=transport,
                serial=serial,
                default_retry_count=1
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
