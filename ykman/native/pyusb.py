# Copyright (c) 2015 Yubico AB
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

from __future__ import absolute_import

import ctypes
import ctypes.util
import os
import sys
import usb.backend.libusb1 as libusb1


def _find_library_local(libname):
    # For .app bundles
    if sys.platform == 'darwin':
        libpath = os.path.join(
            os.path.dirname(
                sys.executable), '../Frameworks', libname + '.dylib')
        if os.path.isfile(libpath):
            return libpath
    else:
        # Look in ykman/native/
        libpath = os.path.join(os.path.dirname(__file__), libname)
        if os.path.isfile(libpath):
            return libpath
        elif sys.platform == 'win32' and os.path.isfile(libpath + '.dll'):
            return libpath + '.dll'


def _load_usb_backend():
    # First try to find backend locally, if not found try the systems.
    try:
        tmp = os.environ['PATH']
        os.environ['PATH'] = ''
        backend = libusb1.get_backend(find_library=_find_library_local)
        if backend is not None:
            return backend
    finally:
        os.environ['PATH'] = tmp

    backend = libusb1.get_backend()
    if backend is not None:
        return backend


def get_usb_backend():
    return _load_usb_backend()


class LibUsb1Version(ctypes.Structure):
    _fields_ = [
        ('major', ctypes.c_uint16),
        ('minor', ctypes.c_uint16),
        ('micro', ctypes.c_uint16),
        ('nano', ctypes.c_uint16),
        ('rc', ctypes.c_char_p),
        ('describe', ctypes.c_char_p)
    ]


def get_usb_backend_version():
    backend = get_usb_backend()
    if backend is None:
        return None
    elif isinstance(backend, libusb1._LibUSB):
        lib = backend.lib
        lib.libusb_get_version.restype = ctypes.POINTER(LibUsb1Version)
        version = lib.libusb_get_version().contents
        return 'libusb {0.major}.{0.minor}.{0.micro}'.format(version)
