# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from .libloader import load_library
import os
import sys


def use_library(libname, version=None, extra_paths=[]):
    lib = load_library(libname, version, extra_paths)

    def define(func_name, argtypes, restype=None):
        try:
            f = getattr(lib, func_name)
            f.argtypes = argtypes
            f.restype = restype
        except AttributeError:
            print('Undefined symbol: %s' % func_name)

            def error(*args, **kwargs):
                raise Exception('Undefined symbol: %s' % func_name)
            f = error
        return f
    return define


class CLibrary(object):
    """
    Base class for extending to create python wrappers for c libraries.

    Example:
        class Foo(CLibrary):
            foo_func = [c_bool, c_char_p], int

        foo = Foo('libfoo')

        assert foo.foo_func(True, 'Hello!') == 7
    """
    def __init__(self, libname, version=None):
        module_path = sys.modules[self.__class__.__module__].__file__
        extra_paths = [os.path.dirname(module_path)]
        self._lib = use_library(libname, version, extra_paths)

    def __getattribute__(self, name):
        val = object.__getattribute__(self, name)
        if isinstance(val, tuple) and len(val) == 2:
            return self._lib(name, *val)
        return val
