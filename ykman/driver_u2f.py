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

from __future__ import print_function

from .native.u2fh import u2fh, u2fh_devs
from ctypes import POINTER, byref, c_uint, c_size_t, create_string_buffer
from .driver import AbstractDriver, ModeSwitchError
from .util import Mode, TRANSPORT
import os
import struct


INS_SELECT = 0xa4
INS_YK4_CAPABILITIES = 0x1d

OTP_AID = b'\xa0\x00\x00\x05\x27\x20\x01'


if u2fh.u2fh_global_init(1 if 'DEBUG' in os.environ else 0) != 0:
    raise Exception("Unable to initialize libu2f-host")


libversion = u2fh.u2fh_check_version(None).decode('ascii')


U2F_VENDOR_FIRST = 0x40
TYPE_INIT = 0x80
U2FHID_PING = TYPE_INIT | 0x01
U2FHID_YUBIKEY_DEVICE_CONFIG = TYPE_INIT | U2F_VENDOR_FIRST
U2FHID_YK4_CAPABILITIES = TYPE_INIT | U2F_VENDOR_FIRST + 2

class U2FHostError(Exception):
    """Thrown if u2f-host call fails."""

    def __init__(self, errno):
        self.errno = errno
        self.message = '{}: {}'.format(u2fh.u2fh_strerror_name(errno), u2fh.u2fh_strerror(errno))

    def __str__(self):
        return 'u2fh error {}, {}'.format(self.errno, self.message)


class U2FDriver(AbstractDriver):
    """
    libu2f-host based U2F driver
    Version number reported by this driver are minimums determined by heuristics
    """
    transport = TRANSPORT.U2F
    sky = False

    def __init__(self, devs, index, name=''):
        self._devs = devs
        self._index = index
        self._mode = Mode(
            TRANSPORT.U2F | sum(t for t in TRANSPORT if t.name in name))
        if ' NEO ' in name:  # At least 3.0.0
            self._version = (3, 0, 0)
        elif ' 4 ' in name:  # At least 4.0.0
            if self.read_capabilities():
                self._version = (4, 1, 0)  # Capabilities means >= 4.1.0
            else:
                self._version = (4, 0, 0)
        elif 'Security Key' in name:
            self.sky = True

    def read_capabilities(self):
        try:
            return self.sendrecv(U2FHID_YK4_CAPABILITIES, b'\x00')
        except:
            return None

    def sendrecv(self, cmd, data):
        buf_size = c_size_t(1024)
        resp = create_string_buffer(buf_size.value)

        status = u2fh.u2fh_sendrecv(self._devs, self._index, cmd, data,
                                    len(data), resp, byref(buf_size))
        if status != 0:
            raise U2FHostError(status)
        return resp.raw[0:buf_size.value]

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        data = struct.pack('BBH', mode_code, cr_timeout, autoeject_time)
        try:
            self.sendrecv(U2FHID_YUBIKEY_DEVICE_CONFIG, data)
        except U2FHostError:
            raise ModeSwitchError()
    def __del__(self):
        u2fh.u2fh_devs_done(self._devs)


def open_device():
    devs = POINTER(u2fh_devs)()
    status = u2fh.u2fh_devs_init(byref(devs))
    if status != 0:
        raise Exception('u2fh_devs_init error: {}'.format(status))
    max_index = c_uint()
    status = u2fh.u2fh_devs_discover(devs, byref(max_index))
    if status == 0:
        resp = create_string_buffer(1024)
        for index in range(max_index.value + 1):
            buf_size = c_size_t(1024)
            if u2fh.u2fh_get_device_description(
                    devs, index, resp, byref(buf_size)) == 0:
                name = resp.value.decode('utf8')
                if name.startswith('Yubikey') \
                        or name.startswith('Security Key by Yubico'):
                    return U2FDriver(devs, index, name)
