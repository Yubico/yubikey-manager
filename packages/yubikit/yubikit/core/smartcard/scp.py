# Copyright (c) 2023 Yubico AB
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

import abc
import logging
from dataclasses import dataclass, field
from enum import IntEnum, unique
from typing import NamedTuple, Sequence

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from _yubikit_native.scp import (  # noqa: F401
    ScpState as _RustScpState,
)

from .. import BadResponseError

logger = logging.getLogger(__name__)


_DEFAULT_KEY = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"


class SessionKeys(NamedTuple):
    """SCP Session Keys."""

    key_senc: bytes
    key_smac: bytes
    key_srmac: bytes
    key_dek: bytes | None = None


class StaticKeys(NamedTuple):
    """SCP03 Static Keys."""

    key_enc: bytes
    key_mac: bytes
    key_dek: bytes | None = None

    @classmethod
    def default(cls) -> StaticKeys:
        return cls(_DEFAULT_KEY, _DEFAULT_KEY, _DEFAULT_KEY)


@unique
class ScpKid(IntEnum):
    SCP03 = 0x1
    SCP11a = 0x11
    SCP11b = 0x13
    SCP11c = 0x15


class KeyRef(bytes):
    @property
    def kid(self) -> int:
        return self[0]

    @property
    def kvn(self) -> int:
        return self[1]

    def __new__(cls, kid_or_data: int | bytes, kvn: int | None = None):
        """This allows creation by passing either binary data, or kid and kvn."""
        if isinstance(kid_or_data, int):  # kid and kvn
            if kvn is None:
                raise ValueError("Missing kvn")
            data = bytes([kid_or_data, kvn])
        else:  # Binary id and version
            if kvn is not None:
                raise ValueError("kvn can only be provided if kid_or_data is a kid")
            data = kid_or_data

        return super(KeyRef, cls).__new__(cls, data)

    def __init__(self, kid_or_data: int | bytes, kvn: int | None = None):
        if len(self) != 2:
            raise ValueError("Incorrect length")

    def __repr__(self):
        return f"KeyRef(kid=0x{self.kid:02x}, kvn=0x{self.kvn:02x})"

    def __str__(self):
        return repr(self)


@dataclass(frozen=True)
class ScpKeyParams(abc.ABC):
    ref: KeyRef


@dataclass(frozen=True)
class Scp03KeyParams(ScpKeyParams):
    ref: KeyRef = KeyRef(ScpKid.SCP03, 0)
    keys: StaticKeys = StaticKeys.default()


@dataclass(frozen=True)
class Scp11KeyParams(ScpKeyParams):
    pk_sd_ecka: ec.EllipticCurvePublicKey
    # For SCP11 a/c we need an OCE key, with its trust chain
    oce_ref: KeyRef | None = None
    sk_oce_ecka: ec.EllipticCurvePrivateKey | None = None
    # Certificate chain for sk_oce_ecka, leaf-last order
    certificates: Sequence[x509.Certificate] = field(default_factory=list)


class ScpState:
    def __init__(
        self,
        session_keys: SessionKeys,
        mac_chain: bytes = b"\0" * 16,
        enc_counter: int = 1,
    ):
        self._keys = session_keys
        self._state = _RustScpState(
            session_keys.key_senc,
            session_keys.key_smac,
            session_keys.key_srmac,
            mac_chain,
            enc_counter,
        )

    def encrypt(self, data: bytes) -> bytes:
        return bytes(self._state.encrypt(data))

    def mac(self, data: bytes) -> bytes:
        return bytes(self._state.mac(data))

    def unmac(self, data: bytes, sw: int) -> bytes:
        try:
            return bytes(self._state.unmac(data, sw))
        except ValueError as e:
            raise BadResponseError(str(e)) from None

    def decrypt(self, encrypted: bytes) -> bytes:
        try:
            return bytes(self._state.decrypt(encrypted))
        except ValueError as e:
            raise BadResponseError(str(e)) from None
