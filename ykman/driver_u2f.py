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

from .native.u2fh import U2fh, u2fh_devs
from .driver import AbstractDriver, ModeSwitchError
from .util import TRANSPORT, YUBIKEY, PID, MissingLibrary, parse_tlvs
from ctypes import POINTER, byref, c_uint, c_size_t, create_string_buffer
from binascii import b2a_hex
import logging
import weakref
import struct
import six


logger = logging.getLogger(__name__)

INS_SELECT = 0xa4
INS_YK4_CAPABILITIES = 0x1d

U2F_VENDOR_FIRST = 0x40
TYPE_INIT = 0x80
U2FHID_PING = TYPE_INIT | 0x01
U2FHID_YUBIKEY_DEVICE_CONFIG = TYPE_INIT | U2F_VENDOR_FIRST
U2FHID_YK4_CAPABILITIES = TYPE_INIT | U2F_VENDOR_FIRST + 2


try:
    u2fh = U2fh('u2f-host', '0')

    # TODO: Allow debug output
    if u2fh.u2fh_global_init(0) is not 0:
        raise Exception('u2fh_global_init failed!')
    libversion = tuple(int(x) for x in u2fh.u2fh_check_version(None)
                       .decode('ascii').split('.'))
except Exception as e:
    logger.error('libu2f-host not found', exc_info=e)
    u2fh = MissingLibrary(
        'libu2f-host not found, U2F connectability not available!')
    libversion = None


class U2FHostError(Exception):
    """Thrown if u2f-host call fails."""

    def __init__(self, errno):
        self.errno = errno
        self.message = '{}: {}'.format(u2fh.u2fh_strerror_name(errno),
                                       u2fh.u2fh_strerror(errno))

    def __str__(self):
        return 'u2fh error {}, {}'.format(self.errno, self.message)


def check(status):
    if status is not 0:
        raise U2FHostError(status)


def _pid_from_name(name):
    if 'Security Key' in name:
        return PID.SKY_U2F

    if 'Plus' in name:
        return PID.YKP_OTP_U2F

    transports = 0
    for t in TRANSPORT:
        if t.name in name:
            transports += t

    key_type = YUBIKEY.NEO if 'NEO' in name else YUBIKEY.YK4
    return key_type.get_pid(transports)


_instances = weakref.WeakSet()


class U2FDriver(AbstractDriver):
    """
    libu2f-host based U2F driver
    """
    transport = TRANSPORT.U2F

    def __init__(self, devs, index, name):
        self._devs = devs
        self._index = index
        self._pid = _pid_from_name(name)
        _instances.add(self)

        self._version = [0, 0, 0]
        self._capa = b''
        if self.key_type == YUBIKEY.YK4:
            self._version[0] = 4
            try:
                self._capa = self.sendrecv(U2FHID_YK4_CAPABILITIES, b'\x00')
                data = self._capa
                c_len, data = six.indexbytes(data, 0), data[1:]
                data = data[:c_len]
                for tlv in parse_tlvs(data):
                    if tlv.tag == 0x02:
                        self._serial = int(b2a_hex(tlv.value), 16)
                self._version[1] = 2
            except U2FHostError:  # Pre 4.2
                self._version[1] = 1
        elif self.key_type == YUBIKEY.NEO:
            self._version = [3, 2, 0]
        elif self.key_type == YUBIKEY.YKP:
            self._version = [4, 0, 0]

    def read_capabilities(self):
        return self._capa

    def guess_version(self):
        return tuple(self._version), False

    def sendrecv(self, cmd, data):
        buf_size = c_size_t(1024)
        resp = create_string_buffer(buf_size.value)
        check(u2fh.u2fh_sendrecv(self._devs, self._index, cmd, data,
                                 len(data), resp, byref(buf_size)))
        return resp.raw[0:buf_size.value]

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        data = struct.pack('BBH', mode_code, cr_timeout, autoeject_time)
        try:
            self.sendrecv(U2FHID_YUBIKEY_DEVICE_CONFIG, data)
        except U2FHostError:
            raise ModeSwitchError()

    def __del__(self):
        if not _instances.difference({self}):
            u2fh.u2fh_devs_done(self._devs)


def open_devices():
    devs = POINTER(u2fh_devs)()
    check(u2fh.u2fh_devs_init(byref(devs)))
    max_index = c_uint()
    u2fh.u2fh_devs_discover(devs, byref(max_index))
    resp = create_string_buffer(1024)
    for index in range(max_index.value + 1):
        buf_size = c_size_t(1024)
        if u2fh.u2fh_get_device_description(
                devs, index, resp, byref(buf_size)) == 0:
            name = resp.value.decode('utf8')
            if name.startswith('Yubikey') \
                    or name.startswith('Security Key by Yubico'):
                yield U2FDriver(devs, index, name)
