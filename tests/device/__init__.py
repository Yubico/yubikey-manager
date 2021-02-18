from ykman.device import is_fips_version
from inspect import signature, Parameter, isgeneratorfunction
from makefun import wraps

import pytest


def condition(check, message="Condition not satisfied"):
    check_sig = signature(check)

    def deco(func):
        func_sig = signature(func)
        added_params = []
        for p in check_sig.parameters:
            if p not in func_sig.parameters:
                added_params.append(Parameter(p, kind=Parameter.POSITIONAL_OR_KEYWORD))
        new_sig = func_sig.replace(
            parameters=list(func_sig.parameters.values()) + added_params
        )

        if isgeneratorfunction(func):

            def wrapper(*args, **kwargs):
                check_args = {
                    k: v for k, v in kwargs.items() if k in check_sig.parameters
                }
                if not check(**check_args):
                    pytest.skip(message)
                func_args = {
                    k: v for k, v in kwargs.items() if k in func_sig.parameters
                }
                yield from func(**func_args)

        else:

            def wrapper(*args, **kwargs):
                check_args = {
                    k: v for k, v in kwargs.items() if k in check_sig.parameters
                }
                if not check(**check_args):
                    pytest.skip(message)
                func_args = {
                    k: v for k, v in kwargs.items() if k in func_sig.parameters
                }
                return func(**func_args)

        return wraps(func, new_sig=new_sig)(wrapper)

    return deco


def register_condition(cond):
    setattr(condition, cond.__name__, cond)
    return cond


@register_condition
def transport(required_transport):
    return condition(
        lambda transport: transport == required_transport,
        f"Requires {required_transport.name}",
    )


@register_condition
def has_transport(transport):
    return condition(
        lambda info: info.supported_capabilities.get(transport),
        f"Requires {transport.name}",
    )


@register_condition
def capability(capability):
    return condition(
        lambda info, device: capability
        in info.config.enabled_capabilities.get(device.transport, []),
        f"Requires {capability}",
    )


@register_condition
def min_version(major, minor=0, micro=0):
    if isinstance(major, tuple):
        vers = major
    else:
        vers = (major, minor, micro)
    return condition(lambda version: version >= vers, f"Version < {vers}")


@register_condition
def max_version(major, minor=0, micro=0):
    if isinstance(major, tuple):
        vers = major
    else:
        vers = (major, minor, micro)
    return condition(lambda version: version <= vers, f"Version > {vers}")


@register_condition
def fips(status=True):
    return condition(
        lambda version: status == is_fips_version(version), f"Requires FIPS = {status}",
    )
