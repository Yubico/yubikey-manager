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

from .. import Tlv, NotSupportedError, BadResponseError
from ._defs import ApduError, SW
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, hashes, serialization, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from dataclasses import dataclass
from typing import NamedTuple, Tuple, Optional, Union, Callable

import os
import abc
import struct
import logging

logger = logging.getLogger(__name__)


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
    """SCP Session Keys."""

    key_senc: bytes
    key_smac: bytes
    key_srmac: bytes
    key_dek: Optional[bytes] = None


class StaticKeys(NamedTuple):
    """SCP03 Static Keys."""

    key_enc: bytes
    key_mac: bytes
    key_dek: Optional[bytes] = None

    @classmethod
    def default(cls) -> "StaticKeys":
        return cls(_DEFAULT_KEY, _DEFAULT_KEY, _DEFAULT_KEY)

    def derive(self, context: bytes) -> SessionKeys:
        return SessionKeys(
            _derive(self.key_enc, _KEY_ENC, context),
            _derive(self.key_mac, _KEY_MAC, context),
            _derive(self.key_mac, _KEY_RMAC, context),
            self.key_dek,
        )


@dataclass
class ScpKeyParams(abc.ABC):
    kvn: int


@dataclass
class Scp03KeyParams(ScpKeyParams):
    kvn: int = 0
    keys: Union[StaticKeys, SessionKeys] = StaticKeys.default()


@dataclass
class Scp11KeyParams(ScpKeyParams):
    pk_sd_ecka: ec.EllipticCurvePublicKey


SendApdu = Callable[[int, int, int, int, bytes], bytes]


class ScpState:
    def __init__(
        self,
        session_keys: SessionKeys,
        mac_chain: bytes = b"\0" * 16,
        enc_counter: int = 1,
    ):
        self._keys = session_keys
        self._mac_chain = mac_chain
        self._enc_counter = enc_counter

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

    def mac(self, data: bytes) -> bytes:
        next_mac_chain, mac = _calculate_mac(self._keys.key_smac, self._mac_chain, data)
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

    @classmethod
    def scp03_init(
        cls,
        send_apdu: SendApdu,
        key_params: Scp03KeyParams,
        *,
        host_challenge: Optional[bytes] = None,
    ) -> Tuple["ScpState", bytes]:
        logger.debug("Initializing SCP03 handshake")
        host_challenge = host_challenge or os.urandom(8)

        try:
            resp = send_apdu(0x80, 0x50, key_params.kvn, 0, host_challenge)
        except ApduError as e:
            if e.sw == SW.CLASS_NOT_SUPPORTED:
                raise NotSupportedError(
                    "This YubiKey does not support secure messaging"
                )
            raise

        diversification_data = resp[:10]  # noqa: unused
        key_info = resp[10:13]  # noqa: unused
        card_challenge = resp[13:21]
        card_cryptogram = resp[21:29]

        context = host_challenge + card_challenge

        if isinstance(key_params.keys, StaticKeys):
            session_keys = key_params.keys.derive(context)
        else:
            session_keys = key_params.keys

        gen_card_crypto = _derive(
            session_keys.key_smac, _CARD_CRYPTOGRAM, context, 0x40
        )
        if not constant_time.bytes_eq(gen_card_crypto, card_cryptogram):
            # This means wrong keys
            raise BadResponseError("Wrong card cryptogram")

        host_cryptogram = _derive(
            session_keys.key_smac, _HOST_CRYPTOGRAM, context, 0x40
        )

        return cls(session_keys), host_cryptogram

    @classmethod
    def scp11_init(
        cls,
        send_apdu: SendApdu,
        key_params: Scp11KeyParams,
    ) -> "ScpState":
        logger.debug("Initializing SCP11 handshake")

        params = bytes([0x11, 0x00])  # SCP11b
        key_usage = bytes(
            [0x3C]
        )  # AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION
        key_type = bytes([0x88])  # AES
        key_len = bytes([16])  # 128-bit

        # Host ephemeral key
        esk_oce_ecka = ec.generate_private_key(key_params.pk_sd_ecka.curve)
        epk_oce_ecka = esk_oce_ecka.public_key()
        data = Tlv(
            0xA6,
            Tlv(0x90, params)
            + Tlv(0x95, key_usage)
            + Tlv(0x80, key_type)
            + Tlv(0x81, key_len),
        ) + Tlv(
            0x5F49,
            epk_oce_ecka.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            ),
        )

        # No static host key, same as ephemeral
        sk_oce_ecka = esk_oce_ecka

        try:
            resp = send_apdu(0x80, 0x88, key_params.kvn, 0x13, data)
        except ApduError as e:
            if e.sw == SW.CLASS_NOT_SUPPORTED:
                raise NotSupportedError(
                    "This YubiKey does not support secure messaging"
                )
            raise

        epk_sd_ecka_tlv, resp = Tlv.parse_from(resp)
        epk_sd_ecka = Tlv.unpack(0x5F49, epk_sd_ecka_tlv)
        receipt = Tlv.unpack(0x86, resp)

        # Derive keys
        key_agreement_data = data + epk_sd_ecka_tlv
        sharedinfo = key_usage + key_type + key_len

        # GPC v2.3 Amendment F (SCP11) v1.3 §3.1.2 Key Derivation
        keys = X963KDF(hashes.SHA256(), 5 * key_len[0], sharedinfo).derive(
            esk_oce_ecka.exchange(
                ec.ECDH(),
                ec.EllipticCurvePublicKey.from_encoded_point(
                    sk_oce_ecka.curve, epk_sd_ecka
                ),
            )
            + sk_oce_ecka.exchange(ec.ECDH(), key_params.pk_sd_ecka)
        )

        # 5 keys were derived, one for verification of receipt
        ln = key_len[0]
        keys = [keys[i : i + ln] for i in range(0, ln * 5, ln)]
        c = cmac.CMAC(algorithms.AES(keys.pop(0)))
        c.update(key_agreement_data)
        c.verify(receipt)
        # The 4 remaining keys are session keys
        session_keys = SessionKeys(*keys)

        return cls(session_keys, receipt)
