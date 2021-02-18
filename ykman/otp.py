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

from . import __version__
from .scancodes import KEYBOARD_LAYOUT
from yubikit.core.otp import modhex_encode
from yubikit.yubiotp import YubiOtpSession
from yubikit.oath import parse_b32_key
from enum import Enum
from http.client import HTTPSConnection
from typing import Iterable

import re
import json
import struct
import random
import logging

logger = logging.getLogger(__name__)


UPLOAD_HOST = "upload.yubico.com"
UPLOAD_PATH = "/prepare"


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
            f"Upload to YubiCloud failed with status {status}: {content}"
        )
        self.status = status
        self.content = content
        self.errors = [
            e if isinstance(e, PrepareUploadError) else PrepareUploadError[e]
            for e in error_ids
        ]

    def messages(self):
        return [e.message() for e in self.errors]


def prepare_upload_key(
    key,
    public_id,
    private_id,
    serial=None,
    user_agent="python-yubikey-manager/" + __version__,
):
    modhex_public_id = modhex_encode(public_id)
    data = {
        "aes_key": key.hex(),
        "serial": serial or 0,
        "public_id": modhex_public_id,
        "private_id": private_id.hex(),
    }

    httpconn = HTTPSConnection(UPLOAD_HOST, timeout=1)  # nosec

    try:
        httpconn.request(
            "POST",
            UPLOAD_PATH,
            body=json.dumps(data, indent=False, sort_keys=True).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": user_agent},
        )
    except Exception as e:
        logger.error("Failed to connect to %s", UPLOAD_HOST, exc_info=e)
        raise PrepareUploadFailed(None, None, [PrepareUploadError.CONNECTION_FAILED])

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


def is_in_fips_mode(session: YubiOtpSession) -> bool:
    """Check if the OTP application of a FIPS YubiKey is in FIPS approved mode."""
    return session.backend.send_and_receive(0x14, b"", 1) == b"\1"  # type: ignore


DEFAULT_PW_CHAR_BLOCKLIST = ["\t", "\n", " "]


def generate_static_pw(
    length: int,
    keyboard_layout: KEYBOARD_LAYOUT = KEYBOARD_LAYOUT.MODHEX,
    blocklist: Iterable[str] = DEFAULT_PW_CHAR_BLOCKLIST,
) -> str:
    """Generate a random password."""
    chars = [k for k in keyboard_layout.value.keys() if k not in blocklist]
    sr = random.SystemRandom()
    return "".join([sr.choice(chars) for _ in range(length)])


def parse_oath_key(val: str) -> bytes:
    """Parse a secret key encoded as either Hex or Base32."""
    val = val.upper()
    if re.match(r"^([0-9A-F]{2})+$", val):  # hex
        return bytes.fromhex(val)
    else:
        # Key should be b32 encoded
        return parse_b32_key(val)


def format_oath_code(response: bytes, digits: int = 6) -> str:
    """Formats an OATH code from a hash response."""
    offs = response[-1] & 0xF
    code = struct.unpack_from(">I", response[offs:])[0] & 0x7FFFFFFF
    return ("%%0%dd" % digits) % (code % 10 ** digits)


def time_challenge(timestamp: int, period: int = 30) -> bytes:
    """Formats a HMAC-SHA1 challenge based on an OATH timestamp and period."""
    return struct.pack(">q", int(timestamp // period))
