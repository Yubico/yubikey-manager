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
from ctypes import (Structure, POINTER, c_int, c_uint8, c_uint, c_ubyte,
                    c_char_p)
from neoman.yubicommon.ctypes.libloader import load_library

_lib = load_library('ykpers-1', '1')


def define(name, args, res):
    try:
        fn = getattr(_lib, name)
        fn.argtypes = args
        fn.restype = res
    except AttributeError:
        print "Undefined symbol: %s" % name

        def error(*args, **kwargs):
            raise Exception("Undefined symbol: %s" % name)
        fn = error
    return fn


YK_KEY = type('YK_KEY', (Structure,), {})
YK_STATUS = type('YK_STATUS', (Structure,), {})
YK_TICKET = type('YK_TICKET', (Structure,), {})
YK_CONFIG = type('YK_CONFIG', (Structure,), {})
YK_NAV = type('YK_NAV', (Structure,), {})
YK_FRAME = type('YK_FRAME', (Structure,), {})
YK_NDEF = type('YK_NDEF', (Structure,), {})
YK_DEVICE_CONFIG = type('YK_DEVICE_CONFIG', (Structure,), {})

ykpers_check_version = define('ykpers_check_version', [c_char_p], c_char_p)

yk_init = define('yk_init', [], c_int)
yk_release = define('yk_release', [], c_int)

yk_open_first_key = define('yk_open_first_key', [], POINTER(YK_KEY))
yk_close_key = define('yk_close_key', [POINTER(YK_KEY)], c_int)

yk_get_status = define('yk_get_status', [
    POINTER(YK_KEY), POINTER(YK_STATUS)], c_int)
yk_get_serial = define('yk_get_serial', [
    POINTER(YK_KEY), c_uint8, c_uint, POINTER(c_uint)], c_int)
yk_write_device_config = define('yk_write_device_config',
                                [POINTER(YK_KEY), POINTER(YK_DEVICE_CONFIG)],
                                c_int)

ykds_alloc = define('ykds_alloc', [], POINTER(YK_STATUS))
ykds_free = define('ykds_free', [POINTER(YK_STATUS)], None)
ykds_version_major = define('ykds_version_major', [POINTER(YK_STATUS)], c_int)
ykds_version_minor = define('ykds_version_minor', [POINTER(YK_STATUS)], c_int)
ykds_version_build = define('ykds_version_build', [POINTER(YK_STATUS)], c_int)

ykp_alloc_device_config = define('ykp_alloc_device_config', [],
                                 POINTER(YK_DEVICE_CONFIG))
ykp_free_device_config = define('ykp_free_device_config',
                                [POINTER(YK_DEVICE_CONFIG)], c_int)
ykp_set_device_mode = define('ykp_set_device_mode', [POINTER(YK_DEVICE_CONFIG),
                                                     c_ubyte], c_int)

yk_get_key_vid_pid = define('yk_get_key_vid_pid', [POINTER(YK_KEY),
                                                   POINTER(c_int),
                                                   POINTER(c_int)], c_int)

yk_get_capabilities = define('yk_get_capabilities', [POINTER(YK_KEY),
                                                     c_uint8,
                                                     c_uint,
                                                     c_char_p], c_int)

__all__ = [x for x in globals().keys() if x.lower().startswith('yk')]
