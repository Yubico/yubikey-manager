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

from .core import TRANSPORT
from .core.smartcard import SmartCardConnection, SmartCardProtocol

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import NamedTuple, Tuple, Optional

import struct
import os


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


class StaticKeys(NamedTuple):
    """SCP03 Static Keys."""

    key_enc: bytes
    key_mac: bytes
    key_dek: bytes

    @classmethod
    def default(cls) -> "StaticKeys":
        return cls(_DEFAULT_KEY, _DEFAULT_KEY, _DEFAULT_KEY)


class SessionKeys(NamedTuple):
    """SCP03 Session Keys."""

    key_senc: bytes
    key_smac: bytes
    key_srmac: bytes


class Scp03Session:
    def __init__(
        self,
        connection: SmartCardConnection,
        session_keys: SessionKeys,
        mac_chain: bytes,
    ):
        self._connection = connection
        self._keys = session_keys
        self._mac_chain = mac_chain
        self._enc_counter = 1

    @classmethod
    def init_session(
        cls, connection: SmartCardConnection, static_keys: StaticKeys
    ) -> "Scp03Session":
        protocol = SmartCardProtocol(connection)

        host_challenge = os.urandom(8)
        resp = protocol.send_apdu(0x80, 0x50, 0, 0, host_challenge)
        # diversification_data = resp[:10]
        # key_info = resp[10:13]
        card_challenge = resp[13:21]
        card_cryptogram = resp[21:29]

        context = host_challenge + card_challenge

        session_keys = SessionKeys(
            _derive(static_keys.key_enc, _KEY_ENC, context),
            _derive(static_keys.key_mac, _KEY_MAC, context),
            _derive(static_keys.key_mac, _KEY_RMAC, context),
        )

        gen_card_crypto = _derive(
            session_keys.key_smac, _CARD_CRYPTOGRAM, context, 0x40
        )
        if not constant_time.bytes_eq(gen_card_crypto, card_cryptogram):
            raise Exception("Wrong card cryptogram")  # TODO

        host_cryptogram = _derive(
            session_keys.key_smac, _HOST_CRYPTOGRAM, context, 0x40
        )

        msg = (
            struct.pack("!BBBBB", 0x84, 0x82, 0x33, 0, len(host_cryptogram) + 8)
            + host_cryptogram
        )
        mac_chain, mac = _calculate_mac(session_keys.key_smac, b"\0" * 16, msg)
        protocol.send_apdu(0x84, 0x82, 0x33, 0, host_cryptogram + mac)

        return cls(connection, session_keys, mac_chain)

    def send_and_receive(self, apdu: bytes) -> Tuple[bytes, int]:
        cla, ins, p1, p2 = apdu[:4]

        key = algorithms.AES(self._keys.key_senc)
        cipher = Cipher(key, modes.ECB(), backend=default_backend())  # nosec ECB
        counter = int.to_bytes(self._enc_counter, 15, "big")
        encryptor = cipher.encryptor()
        iv_send = encryptor.update(b"\x00" + counter) + encryptor.finalize()
        encryptor = cipher.encryptor()
        iv_recv = encryptor.update(b"\x80" + counter) + encryptor.finalize()

        # TODO: Handle extended APDUs?
        msg = apdu[5:]
        padlen = 15 - len(msg) % 16
        msg += b"\x80"
        msg = msg.ljust(len(msg) + padlen, b"\0")

        cipher = Cipher(key, modes.CBC(iv_send), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(msg) + encryptor.finalize()

        wrapped = bytes([0x84 | cla, ins, p1, p2, len(encrypted) + 8]) + encrypted
        next_mac_chain, mac = _calculate_mac(
            self._keys.key_smac, self._mac_chain, wrapped
        )
        wrapped += mac

        resp, sw = self._connection.send_and_receive(wrapped)
        data, mac = resp[:-8], resp[-8:]
        rmac = _calculate_mac(
            self._keys.key_srmac, next_mac_chain, data + struct.pack("!H", sw)
        )[1]
        if not constant_time.bytes_eq(mac, rmac):
            raise Exception("Wrong MAC")  # TODO

        cipher = Cipher(key, modes.CBC(iv_recv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        decrypted = decrypted.rstrip(b"\x00")[:-1]

        self._enc_counter += 1
        self._mac_chain = next_mac_chain

        return decrypted, sw


class Scp03Connection(SmartCardConnection):
    def __init__(
        self,
        connection: SmartCardConnection,
        static_keys: StaticKeys,
    ):
        self._connection = connection
        self._keys = static_keys
        self._session: Optional[Scp03Session] = None

    @property
    def transport(self) -> TRANSPORT:
        return self._connection.transport

    def send_and_receive(self, apdu: bytes) -> Tuple[bytes, int]:
        # If a new AID is selected, perform the session initialization
        if apdu[:4] == b"\x00\xa4\x04\x00":
            resp = self._connection.send_and_receive(apdu)
            self._session = Scp03Session.init_session(self._connection, self._keys)
            return resp

        if self._session:
            return self._session.send_and_receive(apdu)
        raise Exception("No SCP03 session established")
