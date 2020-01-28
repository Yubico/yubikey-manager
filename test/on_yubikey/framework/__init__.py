from __future__ import print_function
import click
import os
import sys
import unittest
import time

from ykman.descriptor import list_devices


_skip = True

_test_serials = os.environ.get('DESTRUCTIVE_TEST_YUBIKEY_SERIALS')
_serials_present = set()
_no_prompt = os.environ.get('DESTRUCTIVE_TEST_DO_NOT_PROMPT') == 'TRUE'
_versions = {}

if _test_serials is not None:
    start_time = time.time()
    print('Initiating device discovery...')

    _test_serials = set(int(s) for s in _test_serials.split(','))

    for dev in list_devices():
        print('{:.3f} {}'.format(time.time() - start_time, dev))
        _serials_present.add(dev.serial)
        _versions[dev.serial] = dev.version
        dev.close()

    _unwanted_serials = _serials_present.difference(_test_serials)

    if len(_unwanted_serials) != 0:
        print('Encountered YubiKeys not listed in serial numbers to be used '
              'for the test: {}'.format(_unwanted_serials),
              file=sys.stderr)
        sys.exit(1)

    if _serials_present != _test_serials:
        print('Test YubiKeys missing: {}'
              .format(_test_serials.difference(_serials_present)),
              file=sys.stderr)
        sys.exit(1)

    _skip = False

    if not _no_prompt:
        click.confirm(
            'Run integration tests? This will erase data on the YubiKeys'
            ' with serial numbers: {}. Make sure these are all keys used for'
            ' development.'.format(_serials_present),
            abort=True)

    end_time = time.time()
    print('Device discovery finished in {:.3f} s'.format(end_time - start_time))


def exactly_one_yubikey_present():
    return len(_serials_present) == 1


def _get_test_method_names(test_class):
    return set(
        attr_name for attr_name in dir(test_class)
        if attr_name.startswith('test')
    )


destructive_tests_not_activated = (
    _skip, 'DESTRUCTIVE_TEST_YUBIKEY_SERIALS == None')


@unittest.skipIf(*destructive_tests_not_activated)
class DestructiveYubikeyTestCase(unittest.TestCase):
    pass
