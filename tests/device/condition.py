from inspect import signature, Parameter, isgeneratorfunction
from makefun import wraps

import pytest


def check(check, message="Condition not satisfied"):
    check_sig = signature(check)
    message = check.__doc__ or message

    def deco(func):
        func_sig = signature(func)
        added_params = []
        for p in check_sig.parameters:
            if p not in func_sig.parameters:
                added_params.append(Parameter(p, kind=Parameter.POSITIONAL_OR_KEYWORD))
        new_sig = func_sig.replace(
            parameters=list(func_sig.parameters.values()) + added_params
        )

        def make_func_args(args, kwargs):
            check_args = {k: v for k, v in kwargs.items() if k in check_sig.parameters}
            if not check(**check_args):
                pytest.skip(message)
            return {k: v for k, v in kwargs.items() if k in func_sig.parameters}

        if isgeneratorfunction(func):

            def wrapper(*args, **kwargs):
                yield from func(**make_func_args(args, kwargs))

        else:

            def wrapper(*args, **kwargs):
                return func(**make_func_args(args, kwargs))

        return wraps(func, new_sig=new_sig)(wrapper)

    return deco


def transport(required_transport):
    return check(
        lambda transport: transport == required_transport,
        f"Requires {required_transport.name}",
    )


def has_transport(transport):
    return check(
        lambda info: info.supported_capabilities.get(transport),
        f"Requires {transport.name}",
    )


def capability(capability, transport=None):
    return check(
        lambda info, device: capability
        in info.config.enabled_capabilities.get(transport or device.transport, []),
        f"Requires {capability}",
    )


def min_version(major, minor=0, micro=0):
    if isinstance(major, tuple):
        vers = major
    else:
        vers = (major, minor, micro)
    return check(lambda version: version >= vers, f"Version < {vers}")


def max_version(major, minor=0, micro=0):
    if isinstance(major, tuple):
        vers = major
    else:
        vers = (major, minor, micro)
    return check(lambda version: version <= vers, f"Version > {vers}")


def yk4_fips(status=True):
    return check(
        lambda info: status == (info.is_fips and info.version[0] == 4),
        f"Requires YK4 FIPS = {status}",
    )
