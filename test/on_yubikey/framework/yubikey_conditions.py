from ykman.device import is_fips_version
from yubikit.core import TRANSPORT
from . import _get_test_method_names


def yubikey_condition(condition):
    """
    Apply this decorator to a function with the signature:
    `ykman.device.YubiKey => Boolean`.

    This makes the decorated function usable as a condition decorator for test
    methods. The decorated function should return `True` if the `YubiKey`
    argument matches the condition - and tests with this condition should run
    with that YubiKey - and `False` otherwise.
    """

    def decorate_method(method):
        method_conditions = (
            getattr(method, "_yubikey_conditions")
            if "_yubikey_conditions" in dir(method)
            else set()
        )
        method_conditions.add(condition)
        setattr(method, "_yubikey_conditions", method_conditions)
        return method

    def decorate_class(cls):
        for method_name in _get_test_method_names(cls):
            setattr(cls, method_name, decorate_method(getattr(cls, method_name)))
        return cls

    def decorate(method_or_class):
        if type(method_or_class) is type:
            return decorate_class(method_or_class)
        else:
            return decorate_method(method_or_class)

    return decorate


@yubikey_condition
def is_fips(info):
    return is_fips_version(info.version)


@yubikey_condition
def is_not_fips(info):
    return not is_fips_version(info.version)


@yubikey_condition
def is_neo(info):
    return info.version < (4, 0, 0)


@yubikey_condition
def is_not_neo(info):
    return info.version >= (4, 0, 0)


@yubikey_condition
def supports_piv_attestation(info):
    return info.version >= (4, 3, 0)


@yubikey_condition
def not_supports_piv_attestation(info):
    return info.version < (4, 3, 0)


@yubikey_condition
def supports_piv_pin_policies(info):
    return info.version >= (4, 0, 0)


@yubikey_condition
def supports_piv_touch_policies(info):
    return info.version >= (4, 0, 0)


@yubikey_condition
def is_roca(info):
    return (4, 2, 0) <= info.version < (4, 3, 5)


@yubikey_condition
def is_not_roca(info):
    return not (4, 2, 0) <= info.version < (4, 3, 5)


@yubikey_condition
def can_write_config(info):
    return info.version >= (5, 0, 0)


@yubikey_condition
def has_nfc(info):
    return info.has_transport(TRANSPORT.NFC)


def version_min(min_version):
    return yubikey_condition(lambda info: info.version >= min_version)


def version_in_range(min_inclusive, max_inclusive):
    return yubikey_condition(
        lambda info: min_inclusive <= info.version <= max_inclusive
    )


def version_not_in_range(min_inclusive, max_inclusive):
    return yubikey_condition(
        lambda info: info.version < min_inclusive or info.version > max_inclusive
    )
