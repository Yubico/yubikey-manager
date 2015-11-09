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


from .native.ykpers import *
from ctypes import POINTER, byref, c_int, c_uint, c_size_t, create_string_buffer
from .driver import AbstractDriver
from .util import Mode, CAPABILITY
import os


INS_SELECT = 0xa4
INS_YK4_CAPABILITIES = 0x1d


if not yk_init():
    raise Exception("Unable to initialize libykpers")


libversion = ykpers_check_version(None)


class OTPDriver(AbstractDriver):
    """
    libykpers based OTP driver
    """
    transport = 'OTP'

    def __init__(self, dev):
        self._dev = dev
        self._version = self._read_version()
        self._mode = self._read_mode()

    def _read_version(self):
        status = ykds_alloc()
        try:
            if yk_get_status(self._dev, status):
                return (
                    ykds_version_major(status),
                    ykds_version_minor(status),
                    ykds_version_build(status)
                )
            else:
                return (0, 0, 0)
        finally:
            ykds_free(status)

    def _read_mode(self):
        if self.version < (3, 0, 0):
            return Mode(otp=True)

        vid = c_int()
        pid = c_int()
        yk_get_key_vid_pid(self._dev, byref(vid), byref(pid))
        mode = 0x07 & pid.value
        if self.version < (4, 0, 0):  # YubiKey NEO PIDs
            if mode == 1:  # mode 1 has PID 0112 and mode 2 has PID 0111
                mode = 2
            elif mode == 2:
                mode = 1
            return Mode.from_code(mode)
        return Mode(otp=mode & CAPABILITY.OTP,
                    u2f=mode & CAPABILITY.U2F,
                    ccid=mode & CAPABILITY.CCID)

    def read_capabilities(self):
        buf_size = c_size_t(1024)
        resp = create_string_buffer(buf_size.value)
        if yk_get_capabilities(self._dev, 0, 0, resp, byref(buf_size)):
            return resp.raw[:buf_size.value]

    def set_mode(self, mode_code):
        config = ykp_alloc_device_config()
        ykp_set_device_mode(config, mode_code)
        try:
            if not yk_write_device_config(self._dev, config):
                raise Exception('Unable to set mode!')
        finally:
            ykp_free_device_config(config)

    def __del__(self):
        yk_close_key(self._dev)


def open_device():
    dev = yk_open_first_key()
    if dev:
        return OTPDriver(dev)
