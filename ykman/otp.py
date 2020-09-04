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

from yubikit.otp import TKTFLAG, CFGFLAG, EXTFLAG

import json
import logging
import time
import struct
from enum import Enum
from six.moves import http_client
from . import __version__
from .util import (
    time_challenge,
    parse_totp_hash,
    format_code,
    hmac_shorten_key,
    modhex_encode,
)
from .scancodes import encode, KEYBOARD_LAYOUT
from binascii import a2b_hex, b2a_hex

logger = logging.getLogger(__name__)


UPLOAD_HOST = "upload.yubico.com"
UPLOAD_PATH = "/prepare"


_ACCESS_CODE_LENGTH = 6
_RESET_ACCESS_CODE = b"\x00" * _ACCESS_CODE_LENGTH


class PrepareUploadError(Enum):
    # Defined here
    CONNECTION_FAILED = "Failed to open HTTPS connection."
    NOT_FOUND = "Upload request not recognized by server."
    SERVICE_UNAVAILABLE = (
        "Service temporarily unavailable, please try again later."  # noqa: E501
    )

    # Defined in upload project
    PRIVATE_ID_INVALID_LENGTH = "Private ID must be 12 characters long."
    PRIVATE_ID_NOT_HEX = (
        "Private ID must consist only of hex characters (0-9A-F)."  # noqa: E501
    )
    PRIVATE_ID_UNDEFINED = "Private ID is required."
    PUBLIC_ID_INVALID_LENGTH = "Public ID must be 12 characters long."
    PUBLIC_ID_NOT_MODHEX = "Public ID must consist only of modhex characters (cbdefghijklnrtuv)."  # noqa: E501
    PUBLIC_ID_NOT_VV = 'Public ID must begin with "vv".'
    PUBLIC_ID_OCCUPIED = "Public ID is already in use."
    PUBLIC_ID_UNDEFINED = "Public ID is required."
    SECRET_KEY_INVALID_LENGTH = "Secret key must be 32 character long."  # nosec
    SECRET_KEY_NOT_HEX = (
        "Secret key must consist only of hex characters (0-9A-F)."  # noqa: E501 # nosec
    )
    SECRET_KEY_UNDEFINED = "Secret key is required."  # nosec
    SERIAL_NOT_INT = "Serial number must be an integer."
    SERIAL_TOO_LONG = "Serial number is too long."

    def message(self):
        return self.value


class PrepareUploadFailed(Exception):
    def __init__(self, status, content, error_ids):
        super(PrepareUploadFailed, self).__init__(
            "Upload to YubiCloud failed with status {}: {}".format(status, content)
        )
        self.status = status
        self.content = content
        self.errors = [
            e if isinstance(e, PrepareUploadError) else PrepareUploadError[e]
            for e in error_ids
        ]

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

    def get_flags(self):
        ext, tkt, cfg = 0, 0, 0
        if self.serial_api_visible:
            ext |= EXTFLAG.SERIAL_API_VISIBLE
        if self.allow_update:
            ext |= EXTFLAG.ALLOW_UPDATE
        if self.append_cr:
            tkt |= TKTFLAG.APPEND_CR

        # Output speed throttling
        if self.pacing == 20:
            cfg |= CFGFLAG.PACING_10MS
        elif self.pacing == 40:
            cfg |= CFGFLAG.PACING_20MS
        elif self.pacing == 60:
            cfg |= CFGFLAG.PACING_10MS | CFGFLAG.PACING_20MS

        if self.numeric_keypad:
            ext |= EXTFLAG.USE_NUMERIC_KEYPAD

        return ext, tkt, cfg


class OtpController(object):
    def __init__(self, app):
        self._app = app
        self._access_code = None

    @property
    def version(self):
        return self._app.version

    @property
    def access_code(self):
        return self._access_code

    @access_code.setter
    def access_code(self, value):
        self._access_code = value

    @property
    def slot_status(self):
        state = self._app.get_config_state()
        return (state.is_configured(1), state.is_configured(2))

    @property
    def serial(self):
        return self._app.get_serial()

    def program_otp(self, slot, key, fixed, uid, config=None):
        if len(key) != 16:
            raise ValueError("key must be 16 bytes")
        if len(uid) != 6:
            raise ValueError("private ID must be 6 bytes")
        if len(fixed) > 16:
            raise ValueError("public ID must be <= 16 bytes")

        ext, tkt, cfg = (config or SlotConfig()).get_flags()

        self._app.write_configuration(
            slot, fixed, uid, key, ext, tkt, cfg, self.access_code, self.access_code,
        )

    def prepare_upload_key(
        self,
        key,
        public_id,
        private_id,
        serial=None,
        user_agent="python-yubikey-manager/" + __version__,
    ):
        modhex_public_id = modhex_encode(public_id)
        data = {
            "aes_key": b2a_hex(key).decode("utf-8"),
            "serial": serial or 0,
            "public_id": modhex_public_id,
            "private_id": b2a_hex(private_id).decode("utf-8"),
        }

        httpconn = http_client.HTTPSConnection(UPLOAD_HOST, timeout=1)  # nosec

        try:
            httpconn.request(
                "POST",
                UPLOAD_PATH,
                body=json.dumps(data, indent=False, sort_keys=True).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": user_agent},
            )
        except Exception as e:
            logger.error("Failed to connect to %s", UPLOAD_HOST, exc_info=e)
            raise PrepareUploadFailed(
                None, None, [PrepareUploadError.CONNECTION_FAILED]
            )

        resp = httpconn.getresponse()
        if resp.status == 200:
            url = json.loads(resp.read().decode("utf-8"))["finish_url"]
            return url
        else:
            resp_body = resp.read()
            logger.debug("Upload failed with status %d: %s", resp.status, resp_body)
            if resp.status == 404:
                raise PrepareUploadFailed(
                    resp.status, resp_body, [PrepareUploadError.NOT_FOUND]
                )
            elif resp.status == 503:
                raise PrepareUploadFailed(
                    resp.status, resp_body, [PrepareUploadError.SERVICE_UNAVAILABLE]
                )
            else:
                try:
                    errors = json.loads(resp_body.decode("utf-8")).get("errors")
                except Exception:
                    errors = []
                raise PrepareUploadFailed(resp.status, resp_body, errors)

    def program_static(
        self, slot, password, keyboard_layout=KEYBOARD_LAYOUT.MODHEX, config=None
    ):
        pw_bytes = encode(password, keyboard_layout=keyboard_layout)
        pw_len = len(pw_bytes)
        if self._app.version < (2, 0, 0):
            raise ValueError("static password requires YubiKey 2.0.0 or later")
        elif self._app.version < (2, 2, 0) and pw_len > 16:
            raise ValueError(
                "password too long, this device supports a "
                "maximum of %d characters" % 16
            )
        elif pw_len > 38:
            raise ValueError(
                "password too long, this device supports a "
                "maximum of %d characters" % 38
            )

        pw_bytes = pw_bytes.ljust(38, b"\0")
        ext, tkt, cfg = (config or SlotConfig()).get_flags()
        self._app.write_configuration(
            slot,
            pw_bytes[:16],
            pw_bytes[16:22],
            pw_bytes[22:],
            ext,
            tkt,
            cfg | CFGFLAG.SHORT_TICKET,
            self.access_code,
            self.access_code,
        )

    def program_chalresp(self, slot, key, touch=False, config=None):
        if self._app.version < (2, 2, 0):
            raise ValueError("challenge-response requires YubiKey 2.2.0 or " "later")
        key = hmac_shorten_key(key, "SHA1")
        if len(key) > 20:
            raise ValueError("key lengths >20 bytes not supported")
        key = key.ljust(22, b"\0")  # Pad key to 22 bytes

        ext, tkt, cfg = (config or SlotConfig()).get_flags()
        if touch:
            cfg |= CFGFLAG.CHAL_BTN_TRIG
        self._app.write_configuration(
            slot,
            b"",
            key[16:],
            key[:16],
            ext,
            tkt | TKTFLAG.CHAL_RESP,
            cfg | CFGFLAG.CHAL_HMAC | CFGFLAG.HMAC_LT64,
            self.access_code,
            self.access_code,
        )

    def calculate(
        self, slot, challenge=None, totp=False, digits=6, event=None, on_keepalive=None
    ):
        if totp:
            if challenge is None:
                challenge = time_challenge(time.time())
            else:
                challenge = time_challenge(challenge)
        else:
            challenge = a2b_hex(challenge)

        resp = self._app.calculate_hmac_sha1(slot, challenge, event, on_keepalive)
        if totp:
            return format_code(parse_totp_hash(resp), digits)
        else:
            return b2a_hex(resp)

    def program_hotp(self, slot, key, imf=0, hotp8=False, config=None):
        if self._app.version < (2, 1, 0):
            raise ValueError("HOTP requires YubiKey 2.1.0 or later")
        key = hmac_shorten_key(key, "SHA1")
        if len(key) > 20:
            raise ValueError("key lengths >20 bytes not supported")
        key = key.ljust(20, b"\0")  # Pad key to 20 bytes
        if imf % 16 != 0:
            raise ValueError("imf must be a multiple of 16")

        ext, tkt, cfg = (config or SlotConfig()).get_flags()
        if hotp8:
            cfg |= CFGFLAG.OATH_HOTP8

        self._app.write_configuration(
            slot,
            b"",
            key[16:] + struct.pack(">H", imf // 16),  # IMF stored as bytes 4-6 of uid
            key[:16],
            ext,
            tkt | TKTFLAG.OATH_HOTP,
            cfg,
            self.access_code,
            self.access_code,
        )

    def zap_slot(self, slot):
        self._app.delete_slot(slot)

    def swap_slots(self):
        if self._app.version < (2, 3, 0):
            raise ValueError("swapping slots requires YubiKey 2.3.0 or later")
        self._app.swap_slots()

    def configure_ndef_slot(self, slot, prefix="https://my.yubico.com/yk/#"):
        self._app.configure_ndef(slot, prefix, self.access_code)

    @property
    def _has_update_access_code_bug(self):
        return (4, 3, 1) < self._app.version < (4, 3, 6)

    def set_access_code(self, slot, new_code=None):
        if self._app.version < (2, 3, 0):
            raise ValueError("Update requires YubiKey 2.3.0 or later")
        if new_code == _RESET_ACCESS_CODE:
            raise ValueError("Cannot set access code to special value zero.")
        if new_code is not None and self._has_update_access_code_bug:
            raise ValueError(
                "This YubiKey firmware does not support updating the access "
                "code after programming the slot. Please set the access "
                "code when initially programming the slot instead."
            )
        if new_code and len(new_code) != _ACCESS_CODE_LENGTH:
            raise ValueError("Wrong length for new access code")

        ext, tkt, cfg = SlotConfig().get_flags()
        self._app.update_configuration(
            slot, ext, tkt, cfg, self.access_code, new_code or _RESET_ACCESS_CODE,
        )
        self.access_code = new_code

    def delete_access_code(self, slot):
        if self._has_update_access_code_bug:
            raise ValueError(
                "This YubiKey firmware does not support deleting the access "
                "code after programming the slot. Please delete and re-program "
                "the slot instead."
            )

        self.set_access_code(slot, None)

    def update_settings(self, slot, config=None):
        ext, tkt, cfg = (config or SlotConfig()).get_flags()

        self._app.update_configuration(
            slot, ext, tkt, cfg, self.access_code, self.access_code,
        )

    @property
    def is_in_fips_mode(self):
        # TODO: Expose this in a better way?
        return self._app.backend.transceive(0x14, b"", 1) == b"\1"
