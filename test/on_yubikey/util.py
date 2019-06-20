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


def _delete_inapplicable_test_methods(dev, test_class):
    for method_name in _get_test_method_names(test_class):
        method = getattr(test_class, method_name)
        if not _device_satisfies_test_conditions(dev, method):
            delattr(test_class, method_name)
    return test_class


def _add_suffix_to_class_name(transport, dev, test_class):
    setattr(test_class, '_original_test_name', test_class.__qualname__)
    fw_version = '.'.join(str(v) for v in dev.version)
    test_class.__qualname__ = f'{test_class.__qualname__}_{transport.name}_{fw_version}_{dev.serial}'  # noqa: E501
    return test_class


def _create_test_classes_for_device(
        transport,
        dev,
        create_test_classes,
        create_test_class_context
):
    context = create_test_class_context(dev, transport)
    for test_class in create_test_classes(context):
        _delete_inapplicable_test_methods(dev, test_class)
        _add_suffix_to_class_name(transport, dev, test_class)
        yield test_class


def _get_test_method_names(test_class):
    return set(
        attr_name for attr_name in dir(test_class)
        if attr_name.startswith('test')
    )


def _multiply_test_classes_by_devices(
        transports,
        create_test_classes,
        create_test_class_context
):
    tests = []
    covered_test_names = {}

    for transport in (t for t in TRANSPORT if transports & t):
        for serial in _test_serials or []:
            with ykman.descriptor.open_device(
                    transports=transport,
                    serial=serial
            ) as dev:
                for test_class in _create_test_classes_for_device(
                        transport,
                        dev,
                        create_test_classes,
                        create_test_class_context
                ):
                    orig_name = test_class._original_test_name
                    test_names = _get_test_method_names(test_class)
                    covered_test_names[orig_name] = (
                        covered_test_names.get(orig_name, set())
                        .union(test_names))
                    for test_method_name in test_names:
                        tests.append(test_class(test_method_name))

    return tests, covered_test_names


def _make_skips_for_uncovered_tests(create_test_classes, covered_test_names):
    for original_test_class in _make_skipped_original_test_cases(
            create_test_classes):
        original_test_names = _get_test_method_names(original_test_class)
        uncovered_test_names = original_test_names.difference(
            covered_test_names.get(
                original_test_class.__qualname__, set()))

        for uncovered_test_name in uncovered_test_names:
            yield original_test_class(uncovered_test_name)


def _make_test_suite(transports, create_test_class_context):
    def decorate(create_test_classes):
        def additional_tests():
            (tests, covered_test_names) = _multiply_test_classes_by_devices(
                transports,
                create_test_classes,
                create_test_class_context
            )

            skipped_tests = _make_skips_for_uncovered_tests(
                create_test_classes, covered_test_names)

            suite = unittest.TestSuite()
            suite.addTests(tests)
            suite.addTests(skipped_tests)

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
