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

from .scancodes import KEYBOARD_LAYOUT
from yubikit.core.otp import modhex_encode
from yubikit.yubiotp import YubiOtpSession
from yubikit.oath import parse_b32_key
from datetime import datetime
from typing import Iterable, Optional

import struct
import random
import logging

logger = logging.getLogger(__name__)


def is_in_fips_mode(session: YubiOtpSession) -> bool:
    """Check if the OTP application of a FIPS YubiKey is in FIPS approved mode.

    :param session: The YubiOTP session.
    """
    return session.backend.send_and_receive(0x14, b"", 1) == b"\1"  # type: ignore


DEFAULT_PW_CHAR_BLOCKLIST = ["\t", "\n", " "]


def generate_static_pw(
    length: int,
    keyboard_layout: KEYBOARD_LAYOUT = KEYBOARD_LAYOUT.MODHEX,
    blocklist: Iterable[str] = DEFAULT_PW_CHAR_BLOCKLIST,
) -> str:
    """Generate a random password.

    :param length: The length of the password.
    :param keyboard_layout: The keyboard layout.
    :param blocklist: The list of characters to block.
    """
    chars = [k for k in keyboard_layout.value.keys() if k not in blocklist]
    sr = random.SystemRandom()
    return "".join([sr.choice(chars) for _ in range(length)])


def parse_oath_key(val: str) -> bytes:
    """Parse a secret key encoded as either Hex or Base32.

    :param val: The secret key.
    """
    try:
        return bytes.fromhex(val)
    except ValueError:
        return parse_b32_key(val)


def format_oath_code(response: bytes, digits: int = 6) -> str:
    """Format an OATH code from a hash response.

    :param response: The response.
    :param digits: The number of digits in the OATH code.
    """
    offs = response[-1] & 0xF
    code = struct.unpack_from(">I", response[offs:])[0] & 0x7FFFFFFF
    return ("%%0%dd" % digits) % (code % 10**digits)


def time_challenge(timestamp: int, period: int = 30) -> bytes:
    """Format a HMAC-SHA1 challenge based on an OATH timestamp and period.

    :param timestamp: The timestamp.
    :param period: The period.
    """
    return struct.pack(">q", int(timestamp // period))


def format_csv(
    serial: int,
    public_id: bytes,
    private_id: bytes,
    key: bytes,
    access_code: Optional[bytes] = None,
    timestamp: Optional[datetime] = None,
) -> str:
    """Produce a CSV line in the "Yubico" format.

    :param serial: The serial number.
    :param public_id: The public ID.
    :param private_id: The private ID.
    :param key: The secret key.
    :param access_code: The access code.
    """
    ts = timestamp or datetime.now()
    return ",".join(
        [
            str(serial),
            modhex_encode(public_id),
            private_id.hex(),
            key.hex(),
            access_code.hex() if access_code else "",
            ts.isoformat(timespec="seconds"),
            "",  # Add trailing comma
        ]
    )
