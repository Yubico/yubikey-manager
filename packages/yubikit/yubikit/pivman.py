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

import struct
from collections.abc import Iterable

from yubikit.core import Tlv
from yubikit.piv import (
    MANAGEMENT_KEY_TYPE,
    OBJECT_ID,
    PivSession,
)

OBJECT_ID_PIVMAN_DATA = 0x5FFF00
OBJECT_ID_PIVMAN_PROTECTED_DATA = OBJECT_ID.PRINTED  # Use slot for printed information.


def _encode_pivman_data(tag: int, entries: Iterable[tuple[int, bytes]]) -> bytes:
    return Tlv(tag, b"".join(Tlv(t, value) for t, value in entries))


class PivmanData:
    def __init__(self, raw_data: bytes = Tlv(0x80)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self._data = data
        self._flags = struct.unpack(">B", data[0x81])[0] if 0x81 in data else None

    def _get_flag(self, mask: int) -> bool:
        return bool((self._flags or 0) & mask)

    def _set_flag(self, mask: int, value: bool) -> None:
        if value:
            self._flags = (self._flags or 0) | mask
        elif self._flags is not None:
            self._flags &= ~mask

    @property
    def mgm_key_protected(self) -> bool:
        return self._get_flag(0x02)

    @mgm_key_protected.setter
    def mgm_key_protected(self, value: bool) -> None:
        self._set_flag(0x02, value)

    @property
    def has_stored_key(self) -> bool:
        return self.mgm_key_protected

    def get_bytes(self) -> bytes:
        data = self._data.copy()
        if self._flags:
            data[0x81] = struct.pack(">B", self._flags)
        else:
            data.pop(0x81, None)
        return _encode_pivman_data(0x80, data.items()) if data else b""


class PivmanProtectedData:
    def __init__(self, raw_data: bytes = Tlv(0x88)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self._data = data
        self.key = data.get(0x89)

    def get_bytes(self) -> bytes:
        data = self._data.copy()
        if self.key is not None:
            data[0x89] = self.key
        else:
            data.pop(0x89, None)
        return _encode_pivman_data(0x88, data.items()) if data else b""


def get_pivman_data(session: PivSession) -> PivmanData:
    """Read out the Pivman data from a YubiKey.

    :param session: The PIV session.
    """
    return PivmanData(_encode_pivman_data(0x80, session._native.get_pivman_data()))


def get_pivman_protected_data(session: PivSession) -> PivmanProtectedData:
    """Read out the Pivman protected data from a YubiKey.

    This function requires PIN verification prior to being called.

    :param session: The PIV session.
    """
    return PivmanProtectedData(
        _encode_pivman_data(0x88, session._native.get_pivman_protected_data())
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

    Storing a key requires PIN verification and access to protected metadata.
    Metadata write errors may occur after the management key has changed.
    """
    algorithm = MANAGEMENT_KEY_TYPE(algorithm)
    native = session._native
    session._management_key_type = MANAGEMENT_KEY_TYPE(native.management_key_type)
    try:
        native.pivman_set_mgm_key(int(algorithm), new_key, touch, store_on_device)
    finally:
        # A metadata write can fail after the key itself has changed.
        session._management_key_type = MANAGEMENT_KEY_TYPE(native.management_key_type)
