# Copyright (c) 2018 Yubico AB
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

import json
import logging
import time
from ctypes import sizeof, byref, c_uint, create_string_buffer
from enum import Enum
from six.moves import http_client
from .driver_otp import ykpers, check, YkpersError
from .util import (time_challenge, parse_totp_hash, format_code,
                   hmac_shorten_key, modhex_encode)
from .scancodes import encode, KEYBOARD_LAYOUT
from . import __version__
from enum import IntEnum, unique
from binascii import a2b_hex, b2a_hex

logger = logging.getLogger(__name__)


UPLOAD_HOST = 'upload.yubico.com'
UPLOAD_PATH = '/prepare'


@unique
class SLOT(IntEnum):
    CONFIG = 0x01
    CONFIG2 = 0x03
    UPDATE1 = 0x04
    UPDATE2 = 0x05
    SWAP = 0x06


SLOTS = [-1, 0x30, 0x38]
_ACCESS_CODE_LENGTH = 6
_RESET_ACCESS_CODE = b'\x00' * _ACCESS_CODE_LENGTH


def slot_to_cmd(slot, update=False):
    if slot == 1:
        return SLOT.UPDATE1 if update else SLOT.CONFIG
    elif slot == 2:
        return SLOT.UPDATE2 if update else SLOT.CONFIG2
    else:
        raise ValueError('slot must be 1 or 2')


class PrepareUploadError(Enum):
    # Defined here
    CONNECTION_FAILED = 'Failed to open HTTPS connection.'
    NOT_FOUND = 'Upload request not recognized by server.'
    SERVICE_UNAVAILABLE = 'Service temporarily unavailable, please try again later.'  # noqa: E501

    # Defined in upload project
    PRIVATE_ID_INVALID_LENGTH = 'Private ID must be 12 characters long.'
    PRIVATE_ID_NOT_HEX = 'Private ID must consist only of hex characters (0-9A-F).'  # noqa: E501
    PRIVATE_ID_UNDEFINED = 'Private ID is required.'
    PUBLIC_ID_INVALID_LENGTH = 'Public ID must be 12 characters long.'
    PUBLIC_ID_NOT_MODHEX = 'Public ID must consist only of modhex characters (cbdefghijklnrtuv).'  # noqa: E501
    PUBLIC_ID_NOT_VV = 'Public ID must begin with "vv".'
    PUBLIC_ID_OCCUPIED = 'Public ID is already in use.'
    PUBLIC_ID_UNDEFINED = 'Public ID is required.'
    SECRET_KEY_INVALID_LENGTH = 'Secret key must be 32 character long.'
    SECRET_KEY_NOT_HEX = 'Secret key must consist only of hex characters (0-9A-F).'  # noqa: E501
    SECRET_KEY_UNDEFINED = 'Secret key is required.'
    SERIAL_NOT_INT = 'Serial number must be an integer.'
    SERIAL_TOO_LONG = 'Serial number is too long.'

    def message(self):
        return self.value


class PrepareUploadFailed(Exception):
    def __init__(self, status, content, error_ids):
        super(PrepareUploadFailed, self).__init__(
            'Upload to YubiCloud failed with status {}: {}'
            .format(status, content))
        self.status = status
        self.content = content
        self.errors = [
            e if isinstance(e, PrepareUploadError) else PrepareUploadError[e]
            for e in error_ids]

    def messages(self):
        return [e.message() for e in self.errors]


class SlotConfig(object):
    def __init__(
            self,
            serial_api_visible=True,
            allow_update=True,
            append_cr=True,
            pacing=None,
            numeric_keypad=False,
    ):
        self.serial_api_visible = serial_api_visible
        self.allow_update = allow_update
        self.append_cr = append_cr
        self.pacing = pacing
        self.numeric_keypad = numeric_keypad


class _SlotConfigContext(object):

    def __init__(self, dev, cmd, conf):
        st = ykpers.ykds_alloc()
        self.cfg = ykpers.ykp_alloc()
        try:
            check(ykpers.yk_get_status(dev, st))
            ykpers.ykp_configure_version(self.cfg, st)
            ykpers.ykp_configure_command(self.cfg, cmd)
        except YkpersError:
            ykpers.ykp_free_config(self.cfg)
            raise
        finally:
            ykpers.ykds_free(st)

        if conf is None:
            conf = SlotConfig()
        self._apply(conf)

    def _apply(self, config):
        if config.serial_api_visible:
            check(ykpers.ykp_set_extflag(self.cfg, 'SERIAL_API_VISIBLE'))
        if config.allow_update:
            check(ykpers.ykp_set_extflag(self.cfg, 'ALLOW_UPDATE'))
        if config.append_cr:
            check(ykpers.ykp_set_tktflag(self.cfg, 'APPEND_CR'))

        # Output speed throttling
        if config.pacing == 20:
            check(ykpers.ykp_set_cfgflag(self.cfg, 'PACING_10MS'))
        elif config.pacing == 40:
            check(ykpers.ykp_set_cfgflag(self.cfg, 'PACING_20MS'))
        elif config.pacing == 60:
            check(ykpers.ykp_set_cfgflag(self.cfg, 'PACING_10MS'))
            check(ykpers.ykp_set_cfgflag(self.cfg, 'PACING_20MS'))

        if config.numeric_keypad:
            check(ykpers.ykp_set_extflag(self.cfg, 'USE_NUMERIC_KEYPAD'))

    def __enter__(self):
        return self.cfg

    def __exit__(self, type, value, traceback):
        ykpers.ykp_free_config(self.cfg)


class OtpController(object):

    def __init__(self, driver):
        self._driver = driver
        self._dev = driver.ykpers_dev
        self._access_code = None

    @property
    def access_code(self):
        return self._access_code

    @access_code.setter
    def access_code(self, value):
        self._access_code = value

    def _create_cfg(self, cmd, conf=None):
        context = _SlotConfigContext(self._dev, cmd, conf)
        if self.access_code is not None:
            check(ykpers.ykp_set_access_code(
                context.cfg, self.access_code, _ACCESS_CODE_LENGTH))

        return context

    @property
    def slot_status(self):
        return self._driver.slot_status

    def program_otp(self, slot, key, fixed, uid, config=None):
        if len(key) != 16:
            raise ValueError('key must be 16 bytes')
        if len(uid) != 6:
            raise ValueError('private ID must be 6 bytes')
        if len(fixed) > 16:
            raise ValueError('public ID must be <= 16 bytes')

        cmd = slot_to_cmd(slot)

        with self._create_cfg(cmd, config) as cfg:
            check(ykpers.ykp_set_fixed(cfg, fixed, len(fixed)))
            check(ykpers.ykp_set_uid(cfg, uid, 6))
            ykpers.ykp_AES_key_from_raw(cfg, key)
            check(ykpers.yk_write_command(
                self._dev,
                ykpers.ykp_core_config(cfg),
                cmd, self.access_code
            ))

    def prepare_upload_key(self, key, public_id, private_id, serial=None,
                           user_agent='python-yubikey-manager/' + __version__):
        modhex_public_id = modhex_encode(public_id)
        data = {
            'aes_key': b2a_hex(key).decode('utf-8'),
            'serial': serial or 0,
            'public_id': modhex_public_id,
            'private_id': b2a_hex(private_id).decode('utf-8'),
        }

        httpconn = http_client.HTTPSConnection(UPLOAD_HOST, timeout=1)
        try:
            httpconn.request('POST', UPLOAD_PATH,
                             body=json.dumps(data, indent=False, sort_keys=True)
                             .encode('utf-8'),
                             headers={
                                 'Content-Type': 'application/json',
                                 'User-Agent': user_agent,
                             })
        except Exception as e:
            logger.error('Failed to connect to %s', UPLOAD_HOST, exc_info=e)
            raise PrepareUploadFailed(
                None, None, [PrepareUploadError.CONNECTION_FAILED])

        resp = httpconn.getresponse()
        if resp.status == 200:
            url = json.loads(resp.read().decode('utf-8'))['finish_url']
            return url
        else:
            resp_body = resp.read()
            logger.debug('Upload failed with status %d: %s',
                         resp.status, resp_body)
            if resp.status == 404:
                raise PrepareUploadFailed(
                    resp.status, resp_body, [PrepareUploadError.NOT_FOUND])
            elif resp.status == 503:
                raise PrepareUploadFailed(
                    resp.status, resp_body,
                    [PrepareUploadError.SERVICE_UNAVAILABLE])
            else:
                try:
                    errors = json.loads(resp_body.decode('utf-8')).get('errors')
                except Exception:
                    errors = []
                raise PrepareUploadFailed(resp.status, resp_body, errors)

    def program_static(
            self,
            slot,
            password,
            keyboard_layout=KEYBOARD_LAYOUT.MODHEX,
            config=None
    ):
        pw_len = len(password)
        if self._driver.version < (2, 0, 0):
            raise ValueError('static password requires YubiKey 2.0.0 or later')
        elif self._driver.version < (2, 2, 0) and pw_len > 16:
            raise ValueError('password too long, this device supports a '
                             'maximum of %d characters' % 16)
        elif pw_len > 38:
            raise ValueError('password too long, this device supports a '
                             'maximum of %d characters' % 38)

        cmd = slot_to_cmd(slot)

        with self._create_cfg(cmd, config) as cfg:
            check(ykpers.ykp_set_cfgflag(cfg, 'SHORT_TICKET'))
            pw_bytes = encode(password, keyboard_layout=keyboard_layout)
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

    def program_chalresp(self, slot, key, touch=False, config=None):
        if self._driver.version < (2, 2, 0):
            raise ValueError('challenge-response requires YubiKey 2.2.0 or '
                             'later')
        key = hmac_shorten_key(key, 'SHA1')
        if len(key) > 20:
            raise ValueError('key lengths >20 bytes not supported')
        cmd = slot_to_cmd(slot)
        key = key.ljust(20, b'\0')  # Pad key to 20 bytes

        with self._create_cfg(cmd, config) as cfg:
            check(ykpers.ykp_set_tktflag(cfg, 'CHAL_RESP'))
            check(ykpers.ykp_set_cfgflag(cfg, 'CHAL_HMAC'))
            check(ykpers.ykp_set_cfgflag(cfg, 'HMAC_LT64'))
            if touch:
                check(ykpers.ykp_set_cfgflag(cfg, 'CHAL_BTN_TRIG'))
            ykpers.ykp_HMAC_key_from_raw(cfg, key)
            check(ykpers.yk_write_command(
                self._dev, ykpers.ykp_core_config(cfg), cmd, self.access_code))

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
        # Pad challenge when < 64 bytes
        challenge = challenge.ljust(
            64, b'\1' if challenge.endswith(b'\0') else b'\0')
        resp = create_string_buffer(64)
        # Some versions of the NEO firmware returns error 11 too often.
        # Give the YubiKey 10 tries to do the calculation.
        for idx in range(10):
            try:
                logger.debug(
                    'Sending a challenge to the device. Slot %s. '
                    'Attempt %s. Wait for touch is %s.', slot, idx + 1,
                    wait_for_touch)
                check(ykpers.yk_challenge_response(
                        self._dev, SLOTS[slot], wait_for_touch,
                        len(challenge), challenge, sizeof(resp), resp))
            except YkpersError as e:
                if idx < 10 and e.errno == 11 and wait_for_touch is True:
                    # Error 11 when wait_for_touch is true is an unexpected
                    # state, let's try again.
                    continue
                elif wait_for_touch is False:
                    logger.debug('Got %s as expected.', e)
                    # NEOs and very old YK4s might still be blinking,
                    # lets try to read the serial to cancel it.
                    ykpers.yk_get_serial(self._dev, 0, 0, byref(c_uint()))
                    raise
                else:
                    logger.debug('YkpersError: %s', e)
                    raise
            # We got a result, break the loop.
            break
        if totp:
            return format_code(parse_totp_hash(resp.raw[:20]), digits)
        else:
            return b2a_hex(resp.raw[:20])

    def program_hotp(self, slot, key, imf=0, hotp8=False, config=None):
        if self._driver.version < (2, 1, 0):
            raise ValueError('HOTP requires YubiKey 2.1.0 or later')
        key = hmac_shorten_key(key, 'SHA1')
        if len(key) > 20:
            raise ValueError('key lengths >20 bytes not supported')
        key = key.ljust(20, b'\0')  # Pad key to 20 bytes
        if imf % 16 != 0:
            raise ValueError('imf must be a multiple of 16')
        cmd = slot_to_cmd(slot)

        with self._create_cfg(cmd, config) as cfg:
            check(ykpers.ykp_set_tktflag(cfg, 'OATH_HOTP'))
            check(ykpers.ykp_set_oath_imf(cfg, imf))
            if hotp8:
                check(ykpers.ykp_set_cfgflag(cfg, 'OATH_HOTP8'))
            ykpers.ykp_HMAC_key_from_raw(cfg, key)
            check(ykpers.yk_write_command(
                self._dev, ykpers.ykp_core_config(cfg), cmd, self.access_code))

    def zap_slot(self, slot):
        check(ykpers.yk_write_command(self._dev, None, slot_to_cmd(slot),
                                      self.access_code))

    def swap_slots(self):
        if self._driver.version < (2, 3, 0):
            raise ValueError('swapping slots requires YubiKey 2.3.0 or later')

        with self._create_cfg(SLOT.SWAP) as cfg:
            ycfg = ykpers.ykp_core_config(cfg)
            check(ykpers.yk_write_command(self._dev, ycfg, SLOT.SWAP, None))

    def configure_ndef_slot(self, slot, prefix='https://my.yubico.com/yk/#'):
        ndef = ykpers.ykp_alloc_ndef()
        try:
            check(ykpers.ykp_construct_ndef_uri(ndef, prefix.encode()))
            check(ykpers.yk_write_ndef2(self._dev, ndef, slot))
        finally:
            ykpers.ykp_free_ndef(ndef)

    @property
    def _has_update_access_code_bug(self):
        return (4, 3, 1) < self._driver.version < (4, 3, 6)

    def set_access_code(self, slot, new_code=None, update=True,
                        allow_zero=False):
        if update and self._driver.version < (2, 3, 0):
            raise ValueError('Update requires YubiKey 2.3.0 or later')
        if not update and new_code is not None:
            raise ValueError('Cannot set new access code unless updating slot')
        if new_code == _RESET_ACCESS_CODE:
            raise ValueError('Cannot set access code to special value zero.')
        if new_code is not None and self._has_update_access_code_bug:
            raise ValueError(
                'This YubiKey firmware does not support updating the access '
                'code after programming the slot. Please set the access '
                'code when initially programming the slot instead.')

        cmd = slot_to_cmd(slot, update)
        with self._create_cfg(cmd) as cfg:
            check(ykpers.ykp_set_access_code(
                cfg, new_code or _RESET_ACCESS_CODE, _ACCESS_CODE_LENGTH))
            ycfg = ykpers.ykp_core_config(cfg)
            check(ykpers.yk_write_command(self._dev, ycfg, cmd,
                                          self.access_code))

            self.access_code = new_code

    def delete_access_code(self, slot):
        if self._has_update_access_code_bug:
            raise ValueError(
                'This YubiKey firmware does not support deleting the access '
                'code after programming the slot. Please delete and re-program '
                'the slot instead.')

        self.set_access_code(slot, None)

    def update_settings(self, slot, config=None):
        cmd = slot_to_cmd(slot, update=True)
        with self._create_cfg(cmd, config) as cfg:
            check(ykpers.yk_write_command(
                self._dev, ykpers.ykp_core_config(cfg), cmd, self.access_code))

    @property
    def is_in_fips_mode(self):
        return self._driver.is_in_fips_mode
