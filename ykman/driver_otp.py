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

import logging
from .native.ykpers import Ykpers
from ctypes import byref, c_int, c_uint, c_size_t, create_string_buffer
from .driver import AbstractDriver, ModeSwitchError, NotSupportedError
from .util import PID, TRANSPORT, Mode, MissingLibrary

logger = logging.getLogger(__name__)


CONFIG1_VALID = 0x01
CONFIG2_VALID = 0x02

CMD_VERIFY_FIPS_MODE = 0x14

MISSING_LIBYKPERS_MSG = 'libykpers not found, OTP functionality not available'

try:
    ykpers = Ykpers('ykpers-1', '1')
    if not ykpers.yk_init():
        raise Exception('yk_init failed.')
    libversion = tuple(int(x) for x in ykpers.ykpers_check_version(None)
                       .decode('ascii').split('.'))
except Exception as e:
    logger.error('libykpers not found', exc_info=e)
    ykpers = MissingLibrary(MISSING_LIBYKPERS_MSG)
    libversion = None


class YkpersError(Exception):
    """Thrown if a ykpers call fails."""

    def __init__(self, errno):
        self.errno = errno
        self.message = ykpers.yk_strerror(errno)

    def __str__(self):
        return 'ykpers error {}, {}'.format(self.errno, self.message)


def check(status):
    if not status:
        raise YkpersError(ykpers.yk_get_errno())


class OTPDriver(AbstractDriver):
    """
    libykpers based OTP driver
    """
    transport = TRANSPORT.OTP

    def __init__(self, dev):
        self._dev = dev
        pid = self._read_pid()
        super(OTPDriver, self).__init__(pid.get_type(), Mode.from_pid(pid))

        self._access_code = None
        self._slot1_valid = False
        self._slot2_valid = False
        self._read_status()

    @property
    def ykpers_dev(self):
        return self._dev

    @property
    def version(self):
        return self._version

    @property
    def slot_status(self):
        return (self._slot1_valid, self._slot2_valid)

    def _read_pid(self):
        vid, pid = c_int(), c_int()
        check(ykpers.yk_get_key_vid_pid(self._dev, byref(vid), byref(pid)))
        return PID(pid.value)

    def _read_status(self):
        status = ykpers.ykds_alloc()
        try:
            if ykpers.yk_get_status(self._dev, status):
                self._version = (
                    ykpers.ykds_version_major(status),
                    ykpers.ykds_version_minor(status),
                    ykpers.ykds_version_build(status)
                )
                touch_level = ykpers.ykds_touch_level(status)
                self._slot1_valid = touch_level & CONFIG1_VALID != 0
                self._slot2_valid = touch_level & CONFIG2_VALID != 0
        finally:
            ykpers.ykds_free(status)

    def read_version(self):
        if self._version[0] == 3:  # This is the OTP applet version.
            return None
        return self._version

    def read_serial(self):
        serial = c_uint()
        if ykpers.yk_get_serial(self._dev, 0, 0, byref(serial)):
            return serial.value
        else:
            logger.debug('Failed to read serial from device.')
            return None  # Serial not visible

    def read_config(self):
        if self._version < (4, 1, 0):
            raise NotSupportedError()

        buf_size = c_size_t(1024)
        resp = create_string_buffer(buf_size.value)
        try:
            check(ykpers.yk_get_capabilities(
                self._dev, 0, 0, resp, byref(buf_size)))
            return resp.raw[:buf_size.value]
        except YkpersError:
            logger.debug(
                'Failed reading config.'
                'OTP interface might be locked, try waiting 3 seconds...')
            import time
            time.sleep(3)
            check(ykpers.yk_get_capabilities(
                self._dev, 0, 0, resp, byref(buf_size)))
            return resp.raw[:buf_size.value]

    def write_config(self, data):
        if self._version < (5, 0, 0):
            raise NotSupportedError()
        if libversion < (1, 19, 0):
            raise NotSupportedError('This action requires libykpers >= 1.19')
        check(ykpers.yk_write_device_info(self._dev, data, len(data)))

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        config = ykpers.ykp_alloc_device_config()
        ykpers.ykp_set_device_mode(config, mode_code)
        ykpers.ykp_set_device_chalresp_timeout(config, cr_timeout)
        ykpers.ykp_set_device_autoeject_time(config, autoeject_time)
        try:
            check(ykpers.yk_write_device_config(self._dev, config))
        except YkpersError:
            raise ModeSwitchError()
        finally:
            ykpers.ykp_free_device_config(config)

    def write_to_and_read_from_key(self, cmd, expected_output_length,
                                   input_bytes=None, read_flags=0,
                                   result_bufsize=16):

        input_bufcount = 0 if input_bytes is None else len(input_bytes)

        result_buf = create_string_buffer(result_bufsize)
        bytes_read = c_uint()

        check(ykpers.yk_write_to_key(self._dev, cmd, input_bytes,
                                     input_bufcount))
        check(ykpers.yk_read_response_from_key(
          self._dev, cmd, read_flags, result_buf, result_bufsize,
          expected_output_length, byref(bytes_read)))

        result = bytearray(result_buf)

        return (result[0:expected_output_length],
                result[0:bytes_read.value],
                result)

    @property
    def is_in_fips_mode(self):
        (result, _, _) = self.write_to_and_read_from_key(
            CMD_VERIFY_FIPS_MODE, expected_output_length=1)
        return result == b'\x01'

    def close(self):
        if self._dev is not None:
            logger.debug('Close %s', self)
            ykpers.yk_close_key(self._dev)
            self._dev = None

    def __del__(self):
        logger.debug('Destroy %s', self)
        self.close()


def open_devices():
    if not libversion:
        logger.error(MISSING_LIBYKPERS_MSG)
        return
    if libversion < (1, 18):
        yield OTPDriver(ykpers.yk_open_first_key())
    else:
        for i in range(255):
            dev = ykpers.yk_open_key(i)
            if not dev:
                logger.debug('Failed to open key at position %s', i)
                break
            logger.debug('Success in opening key at position %s', i)
            yield OTPDriver(dev)
