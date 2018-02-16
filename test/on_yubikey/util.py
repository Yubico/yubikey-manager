from __future__ import print_function
import click
import os
import sys
from ykman.descriptor import (
    get_descriptors, open_device, FailedOpeningDeviceException)
from ykman.util import is_cve201715361_vulnerable_firmware_version
import test.util


_one_yubikey = False
_the_yubikey = None
_skip = True

_test_serial = os.environ.get('DESTRUCTIVE_TEST_YUBIKEY_SERIAL')
_no_prompt = os.environ.get('DESTRUCTIVE_TEST_DO_NOT_PROMPT') == 'TRUE'

if _test_serial is not None:
    _one_yubikey = len(get_descriptors()) == 1

    _skip = False

    if (_one_yubikey):
        if not _no_prompt:
            click.confirm(
                'Run integration tests? This will erase data on the YubiKey'
                ' with serial number: %s. Make sure it is a key used for'
                ' development.'
                % _test_serial,
                abort=True)
        try:
            _the_yubikey = open_device(serial=int(_test_serial), attempts=2)

        except FailedOpeningDeviceException:
            print('Failed to open device. Please make sure you have connected'
                  ' the YubiKey with serial number: {}'.format(_test_serial),
                  file=sys.stderr)
            sys.exit(1)


def _has_mode(mode):
    if not _one_yubikey:
        return False
    return _the_yubikey.mode.has_transport(mode)


def _get_version():
    if not _one_yubikey:
        return None
    return _the_yubikey.version


def is_NEO():
    if _one_yubikey:
        return _get_version() < (4, 0, 0)
    else:
        return False


def _no_attestation():
    if _one_yubikey:
        return _get_version() < (4, 3, 0)
    else:
        return False


def _is_cve201715361_vulnerable_yubikey():
    if _one_yubikey:
        return is_cve201715361_vulnerable_firmware_version(_get_version())
    else:
        return False


def ykman_cli(*args, **kwargs):
    return test.util.ykman_cli(
        '--device', _test_serial,
        *args, **kwargs
    )


def missing_mode(transport):
    return (not _has_mode(transport), transport.name + ' needs to be enabled')


not_one_yubikey = (not _one_yubikey, 'A single YubiKey needs to be connected.')

destructive_tests_not_activated = (
    _skip, 'DESTRUCTIVE_TEST_YUBIKEY_SERIAL == None')

no_attestation = (_no_attestation(), 'Attestation not available.')

skip_roca = (
    _is_cve201715361_vulnerable_yubikey(),
    'Not applicable to CVE-2017-15361 affected YubiKey.')
skip_not_roca = (
    not _is_cve201715361_vulnerable_yubikey(),
    'Applicable only to CVE-2017-15361 affected YubiKey.')