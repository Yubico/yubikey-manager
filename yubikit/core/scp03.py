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

from . import BadResponseError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import NamedTuple, Tuple

import struct


_DEFAULT_KEY = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"

_KEY_ENC = 0x04
_KEY_MAC = 0x06
_KEY_RMAC = 0x07
_CARD_CRYPTOGRAM = 0x00
_HOST_CRYPTOGRAM = 0x01


def _derive(key: bytes, t: int, context: bytes, L: int = 0x80) -> bytes:
    # this only supports aes128
    if L != 0x80 and L != 0x40:
        raise ValueError("L must be 0x40 or 0x80")

    i = b"\0" * 11 + struct.pack("!BBHB", t, 0, L, 1) + context

    c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(i)
    return c.finalize()[: L // 8]


def _calculate_mac(key: bytes, chain: bytes, message: bytes) -> Tuple[bytes, bytes]:
    c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(chain)
    c.update(message)
    chain = c.finalize()
    return chain, chain[:8]


def _init_cipher(key: bytes, counter: int, response=False) -> Cipher:
    encryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()  # nosec ECB
    ).encryptor()
    iv_data = (b"\x80" if response else b"\x00") + int.to_bytes(counter, 15, "big")
    iv = encryptor.update(iv_data) + encryptor.finalize()
    return Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )


class SessionKeys(NamedTuple):
    """SCP03 Session Keys."""

    key_senc: bytes
    key_smac: bytes
    key_srmac: bytes


class StaticKeys(NamedTuple):
    """SCP03 Static Keys."""

    key_enc: bytes
    key_mac: bytes

    @classmethod
    def default(cls) -> "StaticKeys":
        return cls(_DEFAULT_KEY, _DEFAULT_KEY)

    def derive(self, context: bytes) -> SessionKeys:
        return SessionKeys(
            _derive(self.key_enc, _KEY_ENC, context),
            _derive(self.key_mac, _KEY_MAC, context),
            _derive(self.key_mac, _KEY_RMAC, context),
        )


class Scp03State:
    def __init__(
        self,
        session_keys: SessionKeys,
        mac_chain: bytes = b"\0" * 16,
        enc_counter: int = 1,
    ):
        self._keys = session_keys
        self._mac_chain = mac_chain
        self._enc_counter = enc_counter

    def generate_host_cryptogram(self, context: bytes, card_cryptogram: bytes) -> bytes:
        gen_card_crypto = _derive(self._keys.key_smac, _CARD_CRYPTOGRAM, context, 0x40)
        if not constant_time.bytes_eq(gen_card_crypto, card_cryptogram):
            # This means wrong keys
            raise BadResponseError("Wrong card cryptogram")

        return _derive(self._keys.key_smac, _HOST_CRYPTOGRAM, context, 0x40)

    def encrypt(self, data: bytes) -> bytes:
        # Pad the data
        msg = data
        padlen = 15 - len(msg) % 16
        msg += b"\x80"
        msg = msg.ljust(len(msg) + padlen, b"\0")

        # Encrypt
        cipher = _init_cipher(self._keys.key_senc, self._enc_counter)
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(msg) + encryptor.finalize()
        self._enc_counter += 1
        return encrypted

    def mac(self, data: bytes, update: bool = True) -> bytes:
        next_mac_chain, mac = _calculate_mac(self._keys.key_smac, self._mac_chain, data)
        if update:
            self._mac_chain = next_mac_chain
        return mac

    def unmac(self, data: bytes, sw: int) -> bytes:
        msg, mac = data[:-8], data[-8:]
        rmac = _calculate_mac(
            self._keys.key_srmac, self._mac_chain, msg + struct.pack("!H", sw)
        )[1]
        if not constant_time.bytes_eq(mac, rmac):
            raise BadResponseError("Wrong MAC")
        return msg

    def decrypt(self, encrypted: bytes) -> bytes:
        # Decrypt
        cipher = _init_cipher(self._keys.key_senc, self._enc_counter - 1, True)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()

        # Unpad
        unpadded = decrypted.rstrip(b"\x00")
        if unpadded[-1] != 0x80:
            raise BadResponseError("Wrong padding")
        unpadded = unpadded[:-1]

        return unpadded
