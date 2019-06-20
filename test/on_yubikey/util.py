from __future__ import print_function
import click
import functools
import os
import sys
import unittest
import ykman.descriptor
from ykman.util import (
    is_cve201715361_vulnerable_firmware_version, TRANSPORT)
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


def _ykman_cli(serial, *args, **kwargs):
    return test.util.ykman_cli(
        '--device', serial,
        *args, **kwargs
    )


def _filter_yubikeys(self, transport, conditions):
    matched_serials = set()
    for serial in _test_serials:
        with ykman.descriptor.open_device(
                transports=transport, serial=serial) as dev:
            if all(cond(dev) for cond in conditions):
                matched_serials.add(serial)

    if len(matched_serials) == 0:
        self.skipTest('No test YubiKeys matched the test criteria')

    return matched_serials


def _try_test(self, test, serial):
    try:
        return test(
            self,
            functools.partial(_ykman_cli, serial))
    except Exception as e:
        raise AssertionError(
            'Serial {}, version {} failed: {}'
            .format(serial, _versions[serial], str(e)))


def _yubikey_any(transport, *conditions):
    def decorate(f):
        @functools.wraps(f)
        def wrapped(self):
            matched_serials = _filter_yubikeys(self, transport, conditions)
            serial = next(iter(matched_serials))
            return _try_test(self, f, serial)

        return wrapped
    return decorate


def _yubikey_each(transport, *conditions):
    def decorate(f):
        @functools.wraps(f)
        def wrapped(self):
            matched_serials = _filter_yubikeys(self, transport, conditions)
            for serial in matched_serials:
                _try_test(self, f, serial)

        return wrapped
    return decorate


def yubikey_any_ccid(*conditions):
    return _yubikey_any(TRANSPORT.CCID, *conditions)


def yubikey_each_ccid(*conditions):
    return _yubikey_each(TRANSPORT.CCID, *conditions)


def _make_condition_adder(condition):
    def decorate(method):
        method_conditions = (getattr(method, '_yubikey_conditions')
                             if '_yubikey_conditions' in dir(method)
                             else set())
        method_conditions.add(condition)
        setattr(method, '_yubikey_conditions', method_conditions)
        return method
    return decorate


def fips(should_be_fips):
    return _make_condition_adder(lambda dev: should_be_fips == dev.is_fips)


def neo(should_be_neo):
    return _make_condition_adder(
        lambda dev: should_be_neo == (dev.version < (4, 0, 0)))


def piv_attestation(should_support):
    return _make_condition_adder(
        lambda dev: should_support == (dev.version >= (4, 3, 0)))


def roca(should_be_vulnerable):
    return _make_condition_adder(
        lambda dev: should_be_vulnerable ==
        is_cve201715361_vulnerable_firmware_version(dev.version))


def version_min(min_version):
    return _make_condition_adder(lambda dev: dev.version >= min_version)


def _make_skipped_original_test_cases(mktestclasses):
    for test_class in mktestclasses(None):
        yield unittest.skip('No YubiKey available for test')(test_class)


def _make_test_cases(dev, mktestclasses, mktestclasses_arg):
    for test_class in mktestclasses(mktestclasses_arg):
        setattr(test_class, '_original_test_name', test_class.__qualname__)
        fw_version = '.'.join(str(v) for v in dev.version)
        test_class.__qualname__ += f'_{fw_version}_{dev.serial}'

        for attr_name in dir(test_class):
            method = getattr(test_class, attr_name)
            if (attr_name.startswith('test')
                    and '_yubikey_conditions' in dir(method)):
                conditions = getattr(method, '_yubikey_conditions')
                if not all(cond(dev) for cond in conditions):
                    delattr(test_class, attr_name)

        yield test_class


def _make_test_suite(transports, make_mktestclasses_arg):
    def decorate(mktestclasses):
        def additional_tests():
            suite = unittest.TestSuite()

            yubikey_test_names = {}
            for serial in _test_serials or []:
                with ykman.descriptor.open_device(
                        transports=transports,
                        serial=serial
                ) as dev:
                    mktestclasses_arg = make_mktestclasses_arg(dev)
                    for test_case in _make_test_cases(
                            dev, mktestclasses, mktestclasses_arg):
                        orig_name = test_case._original_test_name
                        for attr_name in dir(test_case):
                            if attr_name.startswith('test'):
                                test_names = yubikey_test_names.get(
                                    orig_name, set())
                                test_names.add(attr_name)
                                yubikey_test_names[orig_name] = test_names
                                suite.addTest(test_case(attr_name))

            for original_test_class in _make_skipped_original_test_cases(
                    mktestclasses):
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
    if not isinstance(transports, TRANSPORT):
        raise ValueError('Argument to @device_test_suite must be a TRANSPORT value.')  # noqa: E501

    def make_open_device(dev):
        open_device = functools.partial(
            ykman.descriptor.open_device,
            transports=transports,
            serial=dev.serial
        )
        return open_device

    return _make_test_suite(transports, make_open_device)


def cli_test_suite(transports):
    if not isinstance(transports, TRANSPORT):
        raise ValueError('Argument to @cli_test_suite must be a TRANSPORT value.')  # noqa: E501

    def make_ykman_cli(dev):
        ykman_cli = functools.partial(_ykman_cli, dev.serial)
        return ykman_cli

    return _make_test_suite(transports, make_ykman_cli)


destructive_tests_not_activated = (
    _skip, 'DESTRUCTIVE_TEST_YUBIKEY_SERIALS == None')


@unittest.skipIf(*destructive_tests_not_activated)
class DestructiveYubikeyTestCase(unittest.TestCase):
    pass
