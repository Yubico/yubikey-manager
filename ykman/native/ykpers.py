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

from __future__ import print_function, absolute_import

from ctypes import (Structure, POINTER, c_int, c_uint8, c_uint, c_ubyte,
                    c_char_p, c_ushort, c_size_t, c_ulong)
from .util import CLibrary


YK_KEY = type('YK_KEY', (Structure,), {})
YK_STATUS = type('YK_STATUS', (Structure,), {})
YK_TICKET = type('YK_TICKET', (Structure,), {})
YK_CONFIG = type('YK_CONFIG', (Structure,), {})
YK_NAV = type('YK_NAV', (Structure,), {})
YK_FRAME = type('YK_FRAME', (Structure,), {})
YK_NDEF = type('YK_NDEF', (Structure,), {})
YK_DEVICE_CONFIG = type('YK_DEVICE_CONFIG', (Structure,), {})
YKP_CONFIG = type('YKP_CONFIG', (Structure,), {})


class Ykpers(CLibrary):
    _yk_errno_location = [], POINTER(c_int)
    yk_strerror = [c_int], c_char_p
    ykpers_check_version = [c_char_p], c_char_p

    yk_init = [], bool
    yk_release = [], bool

    yk_open_key = [c_int], POINTER(YK_KEY)
    yk_open_first_key = [], POINTER(YK_KEY)
    yk_close_key = [POINTER(YK_KEY)], bool

    yk_get_status = [POINTER(YK_KEY), POINTER(YK_STATUS)], bool
    yk_get_serial = [POINTER(YK_KEY), c_uint8, c_uint, POINTER(c_uint)], bool
    yk_write_command = [POINTER(YK_KEY), POINTER(YK_CONFIG), c_uint8, c_char_p
                        ], bool
    yk_write_device_config = [POINTER(YK_KEY), POINTER(YK_DEVICE_CONFIG)], bool
    yk_write_to_key = [POINTER(YK_KEY), c_uint8, c_char_p, c_int], bool
    yk_read_response_from_key = [POINTER(YK_KEY), c_uint8, c_uint, c_char_p,
                                 c_uint, c_uint, POINTER(c_uint)], bool

    yk_get_key_vid_pid = [POINTER(YK_KEY), POINTER(c_int), POINTER(c_int)], bool

    yk_get_capabilities = [POINTER(YK_KEY), c_uint8, c_uint, c_char_p], bool

    yk_challenge_response = [
        POINTER(YK_KEY), c_uint8, c_int, c_uint, c_char_p,
        c_uint, c_char_p], bool

    ykds_alloc = [], POINTER(YK_STATUS)
    ykds_free = [POINTER(YK_STATUS)], None
    ykds_version_major = [POINTER(YK_STATUS)], c_int
    ykds_version_minor = [POINTER(YK_STATUS)], c_int
    ykds_version_build = [POINTER(YK_STATUS)], c_int
    ykds_touch_level = [POINTER(YK_STATUS)], c_int

    ykp_alloc = [], POINTER(YKP_CONFIG)
    ykp_free_config = [POINTER(YKP_CONFIG)], bool
    ykp_configure_version = [POINTER(YKP_CONFIG), POINTER(YK_STATUS)], None
    ykp_configure_command = [POINTER(YKP_CONFIG), c_uint8], bool
    ykp_core_config = [POINTER(YKP_CONFIG)], POINTER(YK_CONFIG)

    ykp_alloc_device_config = [], POINTER(YK_DEVICE_CONFIG)
    ykp_free_device_config = [POINTER(YK_DEVICE_CONFIG)], bool
    ykp_set_device_mode = [POINTER(YK_DEVICE_CONFIG), c_ubyte], bool
    ykp_set_device_chalresp_timeout = [POINTER(YK_DEVICE_CONFIG), c_ubyte], bool
    ykp_set_device_autoeject_time = [POINTER(YK_DEVICE_CONFIG), c_ushort], bool
    ykp_set_fixed = [POINTER(YKP_CONFIG), c_char_p, c_size_t], bool
    ykp_set_uid = [POINTER(YKP_CONFIG), c_char_p, c_size_t], bool
    ykp_set_access_code = [POINTER(YKP_CONFIG), c_char_p, c_size_t], bool
    ykp_AES_key_from_raw = [POINTER(YKP_CONFIG), c_char_p], bool
    ykp_HMAC_key_from_raw = [POINTER(YKP_CONFIG), c_char_p], bool
    ykp_set_oath_imf = [POINTER(YKP_CONFIG), c_ulong], bool

    ykp_alloc_ndef = [], POINTER(YK_NDEF)
    ykp_free_ndef = [POINTER(YK_NDEF)], bool
    yk_write_ndef2 = [POINTER(YK_KEY), POINTER(YK_NDEF), c_uint], bool
    ykp_construct_ndef_uri = [POINTER(YK_NDEF), c_char_p], bool

    yk_write_device_info = [POINTER(YK_KEY), c_char_p, c_uint], bool

    def yk_get_errno(self):
        return self._yk_errno_location().contents.value

    def _ykp_set(self, cfg, name, value=True):
        cmd = self._lib(name, [POINTER(YKP_CONFIG), c_uint8], bool)
        return cmd(cfg, value)

    def ykp_set_tktflag(self, cfg, name, value=True):
        return self._ykp_set(cfg, 'ykp_set_tktflag_' + name, value)

    def ykp_set_cfgflag(self, cfg, name, value=True):
        return self._ykp_set(cfg, 'ykp_set_cfgflag_' + name, value)

    def ykp_set_extflag(self, cfg, name, value=True):
        return self._ykp_set(cfg, 'ykp_set_extflag_' + name, value)
