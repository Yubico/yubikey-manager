from yubikit.core import TRANSPORT
from ykman.device import is_fips_version
from inspect import signature, Parameter, isgeneratorfunction
from makefun import wraps

import pytest


def condition(check, message="Condition not satisfied"):
    def deco(func):
        sig = signature(func)
        if "info" not in sig.parameters:
            params = [Parameter("info", kind=Parameter.POSITIONAL_OR_KEYWORD)]
            params.extend(sig.parameters.values())
            sig = sig.replace(parameters=params)

        if isgeneratorfunction(func):

            def wrapper(info, *args, **kwargs):
                if not check(info):
                    pytest.skip(message)
                yield from func(*args, **kwargs)

        else:

            def wrapper(info, *args, **kwargs):
                if not check(info):
                    pytest.skip(message)
                return func(*args, **kwargs)

        return wraps(func, new_sig=sig)(wrapper)

    return deco


def register_condition(cond):
    setattr(condition, cond.__name__, cond)
    return cond


@register_condition
def capability(capability):
    return condition(
        lambda info: capability in info.config.enabled_capabilities[TRANSPORT.USB],
        "Requires %s" % capability,
    )


@register_condition
def min_version(major, minor=0, micro=0):
    if isinstance(major, tuple):
        version = major
    else:
        version = (major, minor, micro)
    return condition(lambda info: info.version >= version, "Version < %s" % (version,))


@register_condition
def max_version(major, minor=0, micro=0):
    if isinstance(major, tuple):
        version = major
    else:
        version = (major, minor, micro)
    return condition(lambda info: info.version <= version, "Version > %s" % (version,))


@register_condition
def fips(status=True):
    return condition(
        lambda info: is_fips_version(info.version), "Requires FIPS = %s" % status
    )
