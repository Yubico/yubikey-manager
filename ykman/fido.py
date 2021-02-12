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

import time
import struct
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SW
from fido2.ctap1 import Ctap1, ApduError

from typing import Optional


U2F_VENDOR_FIRST = 0x40

# FIPS specific INS values
INS_FIPS_VERIFY_PIN = U2F_VENDOR_FIRST + 3
INS_FIPS_SET_PIN = U2F_VENDOR_FIRST + 4
INS_FIPS_RESET = U2F_VENDOR_FIRST + 5
INS_FIPS_VERIFY_FIPS_MODE = U2F_VENDOR_FIRST + 6


def is_in_fips_mode(fido_connection: FidoConnection) -> bool:
    """Check if a YubiKey FIPS is in FIPS approved mode."""
    try:
        ctap = Ctap1(fido_connection)
        ctap.send_apdu(ins=INS_FIPS_VERIFY_FIPS_MODE)
        return True
    except ApduError as e:
        # 0x6a81: Function not supported (PIN not set - not FIPS Mode)
        if e.code == SW.FUNCTION_NOT_SUPPORTED:
            return False
        raise


def fips_change_pin(
    fido_connection: FidoConnection, old_pin: Optional[str], new_pin: str
):
    """Change the PIN on a YubiKey FIPS.

    If no PIN is set, pass None or an empty string as old_pin.
    """
    ctap = Ctap1(fido_connection)

    old_pin_bytes = old_pin.encode() if old_pin else b""
    new_pin_bytes = new_pin.encode()
    new_length = len(new_pin_bytes)

    data = struct.pack("B", new_length) + old_pin_bytes + new_pin_bytes

    ctap.send_apdu(ins=INS_FIPS_SET_PIN, data=data)


def fips_verify_pin(fido_connection: FidoConnection, pin: str):
    """Unlock the YubiKey FIPS U2F module for credential creation."""
    ctap = Ctap1(fido_connection)
    ctap.send_apdu(ins=INS_FIPS_VERIFY_PIN, data=pin.encode())


def fips_reset(fido_connection: FidoConnection):
    """Reset the FIDO module of a YubiKey FIPS.

    Note: This action is only permitted immediately after YubiKey FIPS power-up. It
    also requires the user to touch the flashing button on the YubiKey, and will halt
    until that happens, or the command times out.
    """
    ctap = Ctap1(fido_connection)
    while True:
        try:
            ctap.send_apdu(ins=INS_FIPS_RESET)
            return
        except ApduError as e:
            if e.code == SW.CONDITIONS_NOT_SATISFIED:
                time.sleep(0.5)
            else:
                raise e
