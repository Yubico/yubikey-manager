from __future__ import print_function
import click
import functools
import os
import sys
import test.util
import unittest
import time

from ykman.descriptor import list_devices, open_device
from ykman.util import TRANSPORT


_skip = True

_test_serials = os.environ.get('DESTRUCTIVE_TEST_YUBIKEY_SERIALS')
_no_prompt = os.environ.get('DESTRUCTIVE_TEST_DO_NOT_PROMPT') == 'TRUE'
_versions = {}

if _test_serials is not None:
    start_time = time.time()
    print('Initiating device discovery...')

    _test_serials = set(int(s) for s in _test_serials.split(','))
    _serials_present = set()

    for dev in list_devices():
        print(f'{time.time() - start_time:.3f} {dev}')
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
    print(f'Device discovery finished in {end_time - start_time:.3f} s')


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
        open_device,
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
    '''
    Create test classes for the given device via the given transport.

    A suffix with the transport, device firmware version and device serial
    number is added to the name of each test class returned by
    create_test_classes.

    Each test class is filtered to contain only the tests applicable to the
    device for that test class.

    :param transport: the ykman.util.TRANSPORT to use when opening the device
    :param dev: the ykman.device.YubiKey whose serial number to use when
            opening the device.
    :param create_test_classes: the additional_tests function that was
            decorated with @device_test_suite or @cli_test_suite.
    :param create_test_class_context: a function which, given a
            ykman.device.Yubikey and a ykman.util.TRANSPORT, returns a
            specialized open_device or ykman_cli function for that device and
            transport.
    '''
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
    '''
    Instantiate device-specific versions of test classes for each combination
    of the given transports and the available devices.

    Each test class returned by create_test_classes is instantiated for each
    combination of transport and device.

    :param transports: the ykman.util.TRANSPORTs to use to open the devices.
    :param create_test_classes: the additional_tests function that was
            decorated with @device_test_suite or @cli_test_suite.
    :param create_test_class_context: a function which, given a
            ykman.device.Yubikey and a ykman.util.TRANSPORT, returns a
            specialized open_device or ykman_cli function for that device and
            transport.
    :returns: an iterable of instantiated tests and a dict with original test
            class names mapped to sets of test method names that were
            instantiated.
    '''

    tests = []
    covered_test_names = {}

    for transport in (t for t in TRANSPORT if transports & t):
        for serial in _test_serials or []:
            with open_device(transports=transport, serial=serial) as dev:
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


def _make_test_suite_decorator(transports, create_test_class_context):
    '''
    Create a decorator that will instantiate device-specific versions of the
    test classes returned by the decorated function.

    :param transports: the ykman.util.TRANSPORTs to use to open the devices.
    :param create_test_class_context: a function which, given a
            ykman.device.Yubikey and a ykman.util.TRANSPORT, returns a
            specialized open_device or ykman_cli function for that device and
            transport.
    :returns: a decorator that transforms an additional_tests function into the
            format expected by unittest test discovery.
    '''
    def decorate(create_test_classes):
        def additional_tests():
            start_time = time.time()
            print(f'Starting test instantiation: {create_test_classes.__module__} ...')  # noqa: E501
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

            end_time = time.time()
            print(f'Test instantiation completed in {end_time - start_time:.3f} s')  # noqa: E501

            return suite
        return additional_tests
    return decorate


def device_test_suite(transports):
    '''
    Transform an additional_tests function into the format expected by unittest
    test discovery.

    The decorated function must take one parameter, which will receive a
    specialized ykman.descriptor.open_device function as an argument. This
    open_device function opens a specific YubiKey device, and can be used as if
    that YubiKey is the only one connected. The tests defined in the decorated
    function should use this argument to open a YubiKey.

    The test methods in the annotated function can be decorated with conditions
    from the yubikey_conditions module. These condition decorators will ensure
    that the decorated test is not run with YubiKey devices that do not match
    the conditions.

    :param transports: the ykman.util.TRANSPORTs to use to open YubiKey devices.
    :returns: a decorator that transforms an additional_tests function into the
            format expected by unittest test discovery.
    '''
    if not (isinstance(transports, TRANSPORT) or isinstance(transports, int)):
        raise ValueError('Argument to @device_test_suite must be a TRANSPORT value.')  # noqa: E501
    return _make_test_suite_decorator(transports, _specialize_open_device)


def cli_test_suite(transports):
    '''
    Transform an additional_tests function into the format expected by unittest
    test discovery.

    The decorated function must take one parameter, which will receive a
    specialized test.util.ykman_cli function as an argument. This ykman_cli
    function has the --device option set, so it uses a specific YubiKey device,
    and can be used as if that YubiKey is the only one connected. The tests
    defined in the decorated function should use this argument to run the ykman
    CLI.

    The test methods in the annotated function can be decorated with conditions
    from the yubikey_conditions module. These condition decorators will ensure
    that the decorated test is not run with YubiKey devices that do not match
    the conditions.

    :param transports: the ykman.util.TRANSPORTs required for the functions
            under test.

    TODO: implement transports as described here

    :returns: a decorator that transforms an additional_tests function into the
            format expected by unittest test discovery.
    '''
    if not (isinstance(transports, TRANSPORT) or isinstance(transports, int)):
        raise ValueError('Argument to @cli_test_suite must be a TRANSPORT value.')  # noqa: E501
    return _make_test_suite_decorator(transports, _specialize_ykman_cli)


destructive_tests_not_activated = (
    _skip, 'DESTRUCTIVE_TEST_YUBIKEY_SERIALS == None')


@unittest.skipIf(*destructive_tests_not_activated)
class DestructiveYubikeyTestCase(unittest.TestCase):
    pass
