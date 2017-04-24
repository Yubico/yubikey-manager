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


import six
import time
from .native.ykpers import Ykpers
from ctypes import sizeof, byref, c_uint, c_size_t, create_string_buffer
from .driver import AbstractDriver, ModeSwitchError
from .util import TRANSPORT, MissingLibrary
from .scanmap import us
from ykman.util import time_challenge, parse_totp_hash, format_code
from hashlib import sha1
from binascii import a2b_hex, b2a_hex

INS_SELECT = 0xa4
INS_YK4_CAPABILITIES = 0x1d

SLOT_CONFIG = 0x01
SLOT_CONFIG2 = 0x03
SLOT_UPDATE1 = 0x04
SLOT_UPDATE2 = 0x05
SLOT_SWAP = 0x06
CONFIG1_VALID = 0x01
CONFIG2_VALID = 0x02

SLOTS = [-1, 0x30, 0x38]

try:
    ykpers = Ykpers('ykpers-1', '1')
    if not ykpers.yk_init():
        raise Exception('yk_init failed.')
    libversion = ykpers.ykpers_check_version(None).decode('ascii')
except:
    ykpers = MissingLibrary(
        'libykpers not found, slot functionality not available!')
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


def slot_to_cmd(slot, update=False):
    if slot == 1:
        return SLOT_UPDATE1 if update else SLOT_CONFIG
    elif slot == 2:
        return SLOT_UPDATE2 if update else SLOT_CONFIG2
    else:
        raise ValueError('slot must be 1 or 2')


def get_scan_codes(ascii):
    if isinstance(ascii, six.text_type):
        ascii = ascii.encode('ascii')
    return bytes(bytearray(us.scancodes[c] for c in six.iterbytes(ascii)))


class OTPDriver(AbstractDriver):
    """
    libykpers based OTP driver
    """
    transport = TRANSPORT.OTP

    def __init__(self, dev):

        self._dev = dev
        self._access_code = None
        self._serial = self._read_serial()
        self._slot1_valid = False
        self._slot2_valid = False
        self._status = (0, 0, 0)
        self._read_status()

    @property
    def access_code(self):
        return self._access_code

    @access_code.setter
    def access_code(self, value):
        self._access_code = value

    def _read_serial(self):
        serial = c_uint()
        if ykpers.yk_get_serial(self._dev, 0, 0, byref(serial)):
            return serial.value
        else:
            return None

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

    def read_capabilities(self):
        buf_size = c_size_t(1024)
        resp = create_string_buffer(buf_size.value)
        check(ykpers.yk_get_capabilities(
            self._dev, 0, 0, resp, byref(buf_size)))
        return resp.raw[:buf_size.value]

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

    def _create_cfg(self, cmd):
        st = ykpers.ykds_alloc()
        cfg = ykpers.ykp_alloc()
        try:
            check(ykpers.yk_get_status(self._dev, st))
            ykpers.ykp_configure_version(cfg, st)
            ykpers.ykp_configure_command(cfg, cmd)
            check(ykpers.ykp_set_extflag(cfg, 'SERIAL_API_VISIBLE'))
            check(ykpers.ykp_set_extflag(cfg, 'ALLOW_UPDATE'))
            if self.access_code is not None:
                check(ykpers.ykp_set_access_code(
                    cfg, self.access_code, len(self.access_code)))
            return cfg
        except YkpersError:
            ykpers.ykp_free_config(cfg)
            raise
        finally:
            ykpers.ykds_free(st)

    @property
    def slot_status(self):
        return (self._slot1_valid, self._slot2_valid)

    def program_otp(self, slot, key, fixed, uid, append_cr=True):
        if len(key) != 16:
            raise ValueError('key must be 16 bytes')
        if len(uid) != 6:
            raise ValueError('private ID must be 6 bytes')
        if len(fixed) > 16:
            raise ValueError('public ID must be <= 16 bytes')

        cmd = slot_to_cmd(slot)
        cfg = self._create_cfg(cmd)

        try:
            check(ykpers.ykp_set_fixed(cfg, fixed, len(fixed)))
            check(ykpers.ykp_set_uid(cfg, uid, 6))
            ykpers.ykp_AES_key_from_raw(cfg, key)
            if append_cr:
                check(ykpers.ykp_set_tktflag(cfg, 'APPEND_CR'))
            check(ykpers.yk_write_command(self._dev,
                                          ykpers.ykp_core_config(cfg),
                                          cmd, self.access_code))
        finally:
            ykpers.ykp_free_config(cfg)

    def program_static(self, slot, password, append_cr=True):
        pw_len = len(password)
        if self._version < (2, 0, 0):
            raise ValueError('static password requires YubiKey 2.0.0 or later')
        elif self._version < (2, 2, 0) and pw_len > 16:
            raise ValueError('password too long, this device supports a '
                             'maximum of %d characters' % 16)
        elif pw_len > 38:
            raise ValueError('password too long, this device supports a '
                             'maximum of %d characters' % 38)

        cmd = slot_to_cmd(slot)
        cfg = self._create_cfg(cmd)

        try:
            check(ykpers.ykp_set_cfgflag(cfg, 'SHORT_TICKET'))

            if append_cr:
                check(ykpers.ykp_set_tktflag(cfg, 'APPEND_CR'))

            pw_bytes = get_scan_codes(password)
            if pw_len <= 16:  # All in fixed
                check(ykpers.ykp_set_fixed(cfg, pw_bytes, pw_len))
            elif pw_len <= 16 + 6:  # All in fixed and uid
                check(ykpers.ykp_set_fixed(cfg, pw_bytes[:-6], pw_len - 6))
                check(ykpers.ykp_set_uid(cfg, pw_bytes[-6:], 6))
            else:  # All in fixed + uid + key
                check(ykpers.ykp_set_fixed(cfg, pw_bytes[:-22], pw_len - 22))
                check(ykpers.ykp_set_uid(cfg, pw_bytes[-22:-16], 6))
                ykpers.ykp_AES_key_from_raw(cfg, pw_bytes[-16:])

            check(ykpers.yk_write_command(
                self._dev, ykpers.ykp_core_config(cfg), cmd, self.access_code))
        finally:
            ykpers.ykp_free_config(cfg)

    def program_chalresp(self, slot, key, touch=False):
        if self._version < (2, 2, 0):
            raise ValueError('challenge-response requires YubiKey 2.2.0 or '
                             'later')
        if len(key) > 20:
            raise ValueError('key lengths >20 bytes not supported')
        cmd = slot_to_cmd(slot)
        cfg = self._create_cfg(cmd)
        key = key.ljust(20, b'\0')  # Pad key to 20 bytes
        try:
            check(ykpers.ykp_set_tktflag(cfg, 'CHAL_RESP'))
            check(ykpers.ykp_set_cfgflag(cfg, 'CHAL_HMAC'))
            check(ykpers.ykp_set_cfgflag(cfg, 'HMAC_LT64'))
            if touch:
                check(ykpers.ykp_set_cfgflag(cfg, 'CHAL_BTN_TRIG'))
            ykpers.ykp_HMAC_key_from_raw(cfg, key)
            check(ykpers.yk_write_command(
                self._dev, ykpers.ykp_core_config(cfg), cmd, self.access_code))
        finally:
            ykpers.ykp_free_config(cfg)

    def calculate(
            self, slot, challenge=None, totp=False,
            digits=6, wait_for_touch=True):
        if totp:
            if challenge is None:
                challenge = time_challenge(time.time())
            else:
                challenge = time_challenge(challenge)
        else:
            challenge = a2b_hex(challenge)
        resp = create_string_buffer(64)
        # Some versions of the NEO firmware returns error 11 too often.
        # Give the YubiKey 10 tries to do the calculation.
        for idx in range(10):
            try:
                check(ykpers.yk_challenge_response(
                        self._dev, SLOTS[slot], wait_for_touch,
                        len(challenge), challenge, sizeof(resp), resp))
            except YkpersError as e:
                if idx < 10 and e.errno == 11 and wait_for_touch is True:
                    # Error 11 when wait_for_touch is true is an unexpected
                    # state, let's try again.
                    continue
                else:
                    raise
        if totp:
            return format_code(parse_totp_hash(resp.raw[:20]), digits)
        else:
            return b2a_hex(resp.raw[:20])

    def program_hotp(self, slot, key, imf=0, hotp8=False, append_cr=True):
        if self._version < (2, 1, 0):
            raise ValueError('HOTP requires YubiKey 2.1.0 or later')
        if len(key) > 64:
            key = sha1(key).digest()
        if len(key) > 20:
            raise ValueError('key lengths >20 bytes not supported')
        key += b'\0' * (20 - len(key))
        if imf % 16 != 0:
            raise ValueError('imf must be a multiple of 16')
        cmd = slot_to_cmd(slot)
        cfg = self._create_cfg(cmd)

        try:
            check(ykpers.ykp_set_tktflag(cfg, 'OATH_HOTP'))
            check(ykpers.ykp_set_oath_imf(cfg, imf))
            if hotp8:
                check(ykpers.ykp_set_cfgflag(cfg, 'OATH_HOTP8'))
            if append_cr:
                check(ykpers.ykp_set_tktflag(cfg, 'APPEND_CR'))
            ykpers.ykp_HMAC_key_from_raw(cfg, key)
            check(ykpers.yk_write_command(
                self._dev, ykpers.ykp_core_config(cfg), cmd, self.access_code))
        finally:
            ykpers.ykp_free_config(cfg)

    def zap_slot(self, slot):
        check(ykpers.yk_write_command(self._dev, None, slot_to_cmd(slot),
                                      self.access_code))

    def swap_slots(self):
        if self._version < (2, 3, 0):
            raise ValueError('swapping slots requires YubiKey 2.3.0 or later')
        cfg = self._create_cfg(SLOT_SWAP)
        try:
            ycfg = ykpers.ykp_core_config(cfg)
            check(ykpers.yk_write_command(self._dev, ycfg, SLOT_SWAP, None))
        finally:
            ykpers.ykp_free_config(cfg)

    def set_access_code(self, slot, new_code=None, update=True):
        if update and self._version < (2, 3, 0):
            raise ValueError('Update requires YubiKey 2.3.0 or later')
        if not update and new_code is not None:
            raise ValueError('Cannot set new access code unless updating slot')
        cmd = slot_to_cmd(slot, update)
        cfg = self._create_cfg(cmd)
        try:
            if new_code is None:
                new_code = b'\0' * 6
            check(ykpers.ykp_set_access_code(cfg, new_code, len(new_code)))
            ycfg = ykpers.ykp_core_config(cfg)
            check(ykpers.yk_write_command(self._dev, ycfg, cmd,
                                          self.access_code))
        finally:
            ykpers.ykp_free_config(cfg)

    def update_settings(self, slot, enter=True):
        cmd = slot_to_cmd(slot, update=True)
        cfg = self._create_cfg(cmd)
        if enter:
            check(ykpers.ykp_set_tktflag(cfg, 'APPEND_CR'))
        try:
            check(ykpers.yk_write_command(
                self._dev, ykpers.ykp_core_config(cfg), cmd, self.access_code))
        finally:
            ykpers.ykp_free_config(cfg)

    def __del__(self):
        ykpers.yk_close_key(self._dev)


def open_device():
    dev = ykpers.yk_open_first_key()
    if dev:
        return OTPDriver(dev)
