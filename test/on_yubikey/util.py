from __future__ import print_function
import click
import functools
import os
import sys
import unittest
import ykman.descriptor
from ykman.util import TRANSPORT
import test.util


_skip = True

_test_serials = os.environ.get('DESTRUCTIVE_TEST_YUBIKEY_SERIALS')
_no_prompt = os.environ.get('DESTRUCTIVE_TEST_DO_NOT_PROMPT') == 'TRUE'
_versions = {}

if _test_serials is not None:
    _test_serials = set(int(s) for s in _test_serials.split(','))
    _serials_present = set()

    for dev in ykman.descriptor.list_devices():
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


def _specialize_ykman_cli(dev, _transports):
    '''
    Creates a specialized version of ykman_cli preset with the serial number of
    the given device.
    '''
    return functools.partial(test.util.ykman_cli, '--device', dev.serial)


def _specialize_open_device(dev, transports):
    '''
    Creates a specialized version of open_device which will open the given
    device using the given transport(s).
    '''
    return functools.partial(
        ykman.descriptor.open_device,
        transports=transports,
        serial=dev.serial
    )


def _make_skipped_original_test_cases(create_test_classes):
    for test_class in create_test_classes(None):
        yield unittest.skip('No YubiKey available for test')(test_class)


def _device_satisfies_test_conditions(dev, test_method):
    if '_yubikey_conditions' in dir(test_method):
        conditions = getattr(test_method, '_yubikey_conditions')
        return all(cond(dev) for cond in conditions)
    else:
        return True


def _make_test_classes_for_device(
        transport,
        dev,
        create_test_classes,
        create_test_class_context
):
    context = create_test_class_context(dev, transport)
    for test_class in create_test_classes(context):
        setattr(test_class, '_original_test_name', test_class.__qualname__)
        fw_version = '.'.join(str(v) for v in dev.version)
        test_class.__qualname__ = f'{test_class.__qualname__}_{transport.name}_{fw_version}_{dev.serial}'  # noqa: E501

        for attr_name in dir(test_class):
            method = getattr(test_class, attr_name)
            if attr_name.startswith('test'):
                if not _device_satisfies_test_conditions(dev, method):
                    delattr(test_class, attr_name)

        yield test_class


def _make_test_suite(transports, create_test_class_context):
    def decorate(create_test_classes):
        def additional_tests():
            suite = unittest.TestSuite()
            yubikey_test_names = {}

            for transport in (t for t in TRANSPORT if transports & t):
                for serial in _test_serials or []:
                    with ykman.descriptor.open_device(
                            transports=transport,
                            serial=serial
                    ) as dev:
                        for test_case in _make_test_classes_for_device(
                                transport,
                                dev,
                                create_test_classes,
                                create_test_class_context
                        ):
                            orig_name = test_case._original_test_name
                            for attr_name in dir(test_case):
                                if attr_name.startswith('test'):
                                    test_names = yubikey_test_names.get(
                                        orig_name, set())
                                    test_names.add(attr_name)
                                    yubikey_test_names[orig_name] = test_names
                                    suite.addTest(test_case(attr_name))

            for original_test_class in _make_skipped_original_test_cases(
                    create_test_classes):
                original_test_names = set(
                    attr_name
                    for attr_name in dir(original_test_class)
                    if attr_name.startswith('test')
                )
                uncovered_test_names = original_test_names.difference(
                    yubikey_test_names.get(
                        original_test_class.__qualname__, set()))

                for uncovered_test_name in uncovered_test_names:
                    suite.addTest(original_test_class(uncovered_test_name))

            return suite
        return additional_tests
    return decorate


def device_test_suite(transports):
    if not (isinstance(transports, TRANSPORT) or isinstance(transports, int)):
        raise ValueError('Argument to @device_test_suite must be a TRANSPORT value.')  # noqa: E501
    return _make_test_suite(transports, _specialize_open_device)


def cli_test_suite(transports):
    if not (isinstance(transports, TRANSPORT) or isinstance(transports, int)):
        raise ValueError('Argument to @cli_test_suite must be a TRANSPORT value.')  # noqa: E501
    return _make_test_suite(transports, _specialize_ykman_cli)


destructive_tests_not_activated = (
    _skip, 'DESTRUCTIVE_TEST_YUBIKEY_SERIALS == None')


@unittest.skipIf(*destructive_tests_not_activated)
class DestructiveYubikeyTestCase(unittest.TestCase):
    pass
