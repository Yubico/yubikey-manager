# Copyright (c) 2017 Yubico AB
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

from __future__ import annotations

import logging
import os
import struct
from typing import cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from yubikit.core import Tlv
from yubikit.core.smartcard import SW, ApduError
from yubikit.piv import (
    MANAGEMENT_KEY_TYPE,
    OBJECT_ID,
    PivSession,
)

logger = logging.getLogger(__name__)


OBJECT_ID_PIVMAN_DATA = 0x5FFF00
OBJECT_ID_PIVMAN_PROTECTED_DATA = OBJECT_ID.PRINTED  # Use slot for printed information.


def derive_management_key(pin: str, salt: bytes) -> bytes:
    """Derive a management key from the users PIN and a salt.

    NOTE: This method of derivation is deprecated! Protect the management key using
    PivmanProtectedData instead.

    :param pin: The PIN.
    :param salt: The salt.
    """
    kdf = PBKDF2HMAC(hashes.SHA1(), 24, salt, 10000)  # noqa: S303
    return kdf.derive(pin.encode("utf-8"))


class PivmanData:
    def __init__(self, raw_data: bytes = Tlv(0x80)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self._flags = struct.unpack(">B", data[0x81])[0] if 0x81 in data else None
        self.salt = data.get(0x82)
        self.pin_timestamp = struct.unpack(">I", data[0x83]) if 0x83 in data else None

    def _get_flag(self, mask: int) -> bool:
        return bool((self._flags or 0) & mask)

    def _set_flag(self, mask: int, value: bool) -> None:
        if value:
            self._flags = (self._flags or 0) | mask
        elif self._flags is not None:
            self._flags &= ~mask

    @property
    def puk_blocked(self) -> bool:
        return self._get_flag(0x01)

    @puk_blocked.setter
    def puk_blocked(self, value: bool) -> None:
        self._set_flag(0x01, value)

    @property
    def mgm_key_protected(self) -> bool:
        return self._get_flag(0x02)

    @mgm_key_protected.setter
    def mgm_key_protected(self, value: bool) -> None:
        self._set_flag(0x02, value)

    @property
    def has_protected_key(self) -> bool:
        return self.has_derived_key or self.has_stored_key

    @property
    def has_derived_key(self) -> bool:
        return self.salt is not None

    @property
    def has_stored_key(self) -> bool:
        return self.mgm_key_protected

    def get_bytes(self) -> bytes:
        data = b""
        if self._flags:
            data += Tlv(0x81, struct.pack(">B", self._flags))
        if self.salt is not None:
            data += Tlv(0x82, self.salt)
        if self.pin_timestamp is not None:
            data += Tlv(0x83, struct.pack(">I", self.pin_timestamp))
        return Tlv(0x80, data) if data else b""


class PivmanProtectedData:
    def __init__(self, raw_data: bytes = Tlv(0x88)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self.key = data.get(0x89)

    def get_bytes(self) -> bytes:
        data = b""
        if self.key is not None:
            data += Tlv(0x89, self.key)
        return Tlv(0x88, data) if data else b""


def get_pivman_data(session: PivSession) -> PivmanData:
    """Read out the Pivman data from a YubiKey.

    :param session: The PIV session.
    """
    logger.debug("Reading pivman data")
    try:
        return PivmanData(session.get_object(OBJECT_ID_PIVMAN_DATA))
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            # No data there, initialise a new object.
            logger.debug("No data, initializing blank")
            return PivmanData()
        raise


def get_pivman_protected_data(session: PivSession) -> PivmanProtectedData:
    """Read out the Pivman protected data from a YubiKey.

    This function requires PIN verification prior to being called.

    :param session: The PIV session.
    """
    logger.debug("Reading protected pivman data")
    try:
        return PivmanProtectedData(session.get_object(OBJECT_ID_PIVMAN_PROTECTED_DATA))
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            # No data there, initialise a new object.
            logger.debug("No data, initializing blank")
            return PivmanProtectedData()
        raise
    except Exception:
        raise ValueError(
            f"Invalid data in protected slot ({hex(OBJECT_ID_PIVMAN_PROTECTED_DATA)})"
        )


def pivman_set_mgm_key(
    session: PivSession,
    new_key: bytes,
    algorithm: MANAGEMENT_KEY_TYPE,
    touch: bool = False,
    store_on_device: bool = False,
) -> None:
    """Set a new management key, while keeping PivmanData in sync.

    :param session: The PIV session.
    :param new_key: The new management key.
    :param algorithm: The algorithm for the management key.
    :param touch: If set, touch is required.
    :param store_on_device: If set, the management key is stored on device.
    """
    pivman = get_pivman_data(session)
    pivman_old_bytes = pivman.get_bytes()
    pivman_prot = None

    if store_on_device or (not store_on_device and pivman.has_stored_key):
        # Ensure we have access to protected data before overwriting key
        try:
            pivman_prot = get_pivman_protected_data(session)
        except Exception:
            logger.debug("Failed to initialize protected pivman data", exc_info=True)
            if store_on_device:
                raise

    # Set the new management key
    session.set_management_key(algorithm, new_key, touch)

    if pivman.has_derived_key:
        # Clear salt for old derived keys.
        logger.debug("Clearing salt in pivman data")
        pivman.salt = None

    # Set flag for stored or not stored key.
    pivman.mgm_key_protected = store_on_device

    # Update readable pivman data, if changed
    pivman_bytes = pivman.get_bytes()
    if pivman_old_bytes != pivman_bytes:
        session.put_object(OBJECT_ID_PIVMAN_DATA, pivman_bytes)

    if pivman_prot is not None:
        if store_on_device:
            # Store key in protected pivman data
            logger.debug("Storing key in protected pivman data")
            pivman_prot.key = new_key
            session.put_object(OBJECT_ID_PIVMAN_PROTECTED_DATA, pivman_prot.get_bytes())
        elif pivman_prot.key:
            # If new key should not be stored and there is an old stored key,
            # try to clear it.
            logger.debug("Clearing old key in protected pivman data")
            try:
                pivman_prot.key = None
                session.put_object(
                    OBJECT_ID_PIVMAN_PROTECTED_DATA,
                    pivman_prot.get_bytes(),
                )
            except ApduError:
                logger.debug("No PIN provided, can't clear key...", exc_info=True)


def pivman_change_pin(session: PivSession, old_pin: str, new_pin: str) -> None:
    """Change the PIN, while keeping PivmanData in sync.

    :param session: The PIV session.
    :param old_pin: The old PIN.
    :param new_pin: The new PIN.
    """
    session.change_pin(old_pin, new_pin)

    pivman = get_pivman_data(session)
    if pivman.has_derived_key:
        logger.debug("Has derived management key, update for new PIN")
        session.authenticate(
            derive_management_key(old_pin, cast(bytes, pivman.salt)),
        )
        session.verify_pin(new_pin)
        new_salt = os.urandom(16)
        new_key = derive_management_key(new_pin, new_salt)
        session.set_management_key(MANAGEMENT_KEY_TYPE.TDES, new_key)
        pivman.salt = new_salt
        session.put_object(OBJECT_ID_PIVMAN_DATA, pivman.get_bytes())


def pivman_set_pin_attempts(
    session: PivSession, pin_attempts: int, puk_attempts: int
) -> None:
    """Set the number of PIN and PUK retry attempts, while keeping PivmanData in sync.

    :param session: The PIV session.
    :param pin_attempts: The PIN attempts.
    :param puk_attempts: The PUK attempts.
    """
    session.set_pin_attempts(pin_attempts, puk_attempts)
    pivman = get_pivman_data(session)
    if pivman.puk_blocked:
        pivman.puk_blocked = False
        session.put_object(OBJECT_ID_PIVMAN_DATA, pivman.get_bytes())
