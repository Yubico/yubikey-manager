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

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum, unique
from functools import total_ordering
from typing import NamedTuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from _yubikit_native.sessions import HsmAuthSession as _NativeHsmAuthSession

from .core import (
    InvalidPinError,  # noqa: F401 - re-exported
    Version,
    _override_version,
    int2bytes,
    require_version,
)
from .core.smartcard import (
    ScpKeyParams,
    SmartCardConnection,
)

logger = logging.getLogger(__name__)


# Lengths for parameters
MANAGEMENT_KEY_LEN = 16
CREDENTIAL_PASSWORD_LEN = 16
MIN_LABEL_LEN = 1
MAX_LABEL_LEN = 64

DEFAULT_MANAGEMENT_KEY = (
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

INITIAL_RETRY_COUNTER = 8


@unique
class ALGORITHM(IntEnum):
    """Algorithms for YubiHSM Auth credentials."""

    AES128_YUBICO_AUTHENTICATION = 38
    EC_P256_YUBICO_AUTHENTICATION = 39

    @property
    def key_len(self) -> int:
        if self.name.startswith("AES128"):
            return 16
        elif self.name.startswith("EC_P256"):
            return 32
        raise ValueError("Unknown algorithm")

    @property
    def pubkey_len(self):
        if self.name.startswith("EC_P256"):
            return 64


def _parse_credential_password(credential_password: bytes | str) -> bytes:
    if isinstance(credential_password, str):
        pw = credential_password.encode().ljust(CREDENTIAL_PASSWORD_LEN, b"\0")
    else:
        pw = bytes(credential_password)

    if len(pw) != CREDENTIAL_PASSWORD_LEN:
        raise ValueError(
            "Credential password must be %d bytes long" % CREDENTIAL_PASSWORD_LEN
        )
    return pw


def _parse_label(label: str) -> bytes:
    try:
        parsed_label = label.encode()
    except Exception:
        raise ValueError(label)

    if len(parsed_label) < MIN_LABEL_LEN or len(parsed_label) > MAX_LABEL_LEN:
        raise ValueError(
            "Label must be between %d and %d bytes long"
            % (MIN_LABEL_LEN, MAX_LABEL_LEN)
        )
    return parsed_label


def _password_to_key(password: str) -> tuple[bytes, bytes]:
    """Derive encryption and MAC key from a password.

    :return: A tuple containing the encryption key, and MAC key.
    """
    pw_bytes = password.encode()

    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"Yubico",
        iterations=10000,
        backend=default_backend(),
    ).derive(pw_bytes)
    key_enc, key_mac = key[:16], key[16:]
    return key_enc, key_mac


@total_ordering
@dataclass(order=False, frozen=True)
class Credential:
    """A YubiHSM Auth credential object."""

    label: str
    algorithm: ALGORITHM
    counter: int
    touch_required: bool | None

    def __lt__(self, other):
        a = self.label.lower()
        b = other.label.lower()
        return a < b

    def __eq__(self, other):
        return self.label == other.label

    def __hash__(self) -> int:
        return hash(self.label)


class SessionKeys(NamedTuple):
    """YubiHSM Session Keys."""

    key_senc: bytes
    key_smac: bytes
    key_srmac: bytes


class HsmAuthSession:
    """A session with the YubiHSM Auth application."""

    def __init__(
        self,
        connection: SmartCardConnection,
        scp_key_params: ScpKeyParams | None = None,
    ) -> None:
        native = _NativeHsmAuthSession(connection, scp_key_params)
        self._native = native
        self._version = _override_version.patch(Version(*native.version))
        if self._version != Version(*native.version):
            native.version = tuple(self._version)

        logger.debug(f"YubiHSM Auth session initialized (version={self.version})")

    @property
    def version(self) -> Version:
        """The YubiHSM Auth application version."""
        return self._version

    def reset(self) -> None:
        """Perform a factory reset on the YubiHSM Auth application."""
        self._native.reset()
        logger.info("YubiHSM Auth application data reset performed")

    def list_credentials(self) -> list[Credential]:
        """List YubiHSM Auth credentials on YubiKey"""

        return [
            Credential(label, ALGORITHM(algo), counter, touch_required)
            for label, algo, counter, touch_required in (
                self._native.list_credentials()
            )
        ]

    def put_credential_symmetric(
        self,
        management_key: bytes,
        label: str,
        key_enc: bytes,
        key_mac: bytes,
        credential_password: bytes | str,
        touch_required: bool = False,
    ) -> Credential:
        """Import a symmetric YubiHSM Auth credential.

        :param management_key: The management key.
        :param label: The label of the credential.
        :param key_enc: The static K-ENC.
        :param key_mac: The static K-MAC.
        :param credential_password: The password used to protect
            access to the credential.
        :param touch_required: The touch requirement policy.
        """

        pw = _parse_credential_password(credential_password)
        result = self._native.put_credential_symmetric(
            management_key, label, key_enc, key_mac, pw, touch_required
        )
        logger.info("Credential imported")
        return Credential(result[0], ALGORITHM(result[1]), result[2], result[3])

    def put_credential_derived(
        self,
        management_key: bytes,
        label: str,
        derivation_password: str,
        credential_password: bytes | str,
        touch_required: bool = False,
    ) -> Credential:
        """Import a symmetric YubiHSM Auth credential derived from password.

        :param management_key: The management key.
        :param label: The label of the credential.
        :param derivation_password: The password used to derive the keys from.
        :param credential_password: The password used to protect
            access to the credential.
        :param touch_required: The touch requirement policy.
        """

        pw = _parse_credential_password(credential_password)
        result = self._native.put_credential_derived(
            management_key, label, derivation_password, pw, touch_required
        )
        logger.info("Credential imported")
        return Credential(result[0], ALGORITHM(result[1]), result[2], result[3])

    def put_credential_asymmetric(
        self,
        management_key: bytes,
        label: str,
        private_key: ec.EllipticCurvePrivateKeyWithSerialization,
        credential_password: bytes | str,
        touch_required: bool = False,
    ) -> Credential:
        """Import an asymmetric YubiHSM Auth credential.

        :param management_key: The management key.
        :param label: The label of the credential.
        :param private_key: Private key corresponding to the public
            authentication key object on the YubiHSM.
        :param credential_password: The password used to protect
            access to the credential.
        :param touch_required: The touch requirement policy.
        """

        require_version(self.version, (5, 6, 0))
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("Unsupported curve")

        ln = ALGORITHM.EC_P256_YUBICO_AUTHENTICATION.key_len
        numbers = private_key.private_numbers()
        raw_key = int2bytes(numbers.private_value, ln)

        pw = _parse_credential_password(credential_password)
        result = self._native.put_credential_asymmetric(
            management_key, label, raw_key, pw, touch_required
        )
        logger.info("Credential imported")
        return Credential(result[0], ALGORITHM(result[1]), result[2], result[3])

    def generate_credential_asymmetric(
        self,
        management_key: bytes,
        label: str,
        credential_password: bytes | str,
        touch_required: bool = False,
    ) -> Credential:
        """Generate an asymmetric YubiHSM Auth credential.

        Generates a private key on the YubiKey, whose corresponding
        public key can be retrieved using `get_public_key`.

        :param management_key: The management key.
        :param label: The label of the credential.
        :param credential_password: The password used to protect
            access to the credential.
        :param touch_required: The touch requirement policy.
        """

        require_version(self.version, (5, 6, 0))

        pw = _parse_credential_password(credential_password)
        result = self._native.generate_credential_asymmetric(
            management_key, label, pw, touch_required
        )
        logger.info("Credential imported")
        return Credential(result[0], ALGORITHM(result[1]), result[2], result[3])

    def get_public_key(self, label: str) -> ec.EllipticCurvePublicKey:
        """Get the public key for an asymmetric credential.

        This will return the long-term public key "PK-OCE" for an
        asymmetric credential.

        :param label: The label of the credential.
        """
        require_version(self.version, (5, 6, 0))

        sec1_bytes = self._native.get_public_key(label)
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes(sec1_bytes)
        )

    def delete_credential(self, management_key: bytes, label: str) -> None:
        """Delete a YubiHSM Auth credential.

        :param management_key: The management key.
        :param label: The label of the credential.
        """

        self._native.delete_credential(management_key, label)
        logger.info("Credential deleted")

    def change_credential_password(
        self,
        label: str,
        credential_password: bytes | str,
        new_credential_password: bytes | str,
    ) -> None:
        """Change the password of a YubiHSM Auth credential.

        :param label: The label of the credential.
        :param credential_password: The current credential password.
        :param new_credential_password: The new credential password.
        """
        pw = _parse_credential_password(credential_password)
        new_pw = _parse_credential_password(new_credential_password)
        self._native.change_credential_password(label, pw, new_pw)
        logger.info("Credential password changed")

    def change_credential_password_admin(
        self,
        label: str,
        management_key: bytes,
        new_credential_password: bytes | str,
    ) -> None:
        """Change the password of a YubiHSM Auth credential with management key.

        :param label: The label of the credential.
        :param management_key: The management key.
        :param new_credential_password: The new credential password.
        """
        new_pw = _parse_credential_password(new_credential_password)
        self._native.change_credential_password_admin(management_key, label, new_pw)
        logger.info("Credential password changed")

    def put_management_key(
        self,
        management_key: bytes,
        new_management_key: bytes,
    ) -> None:
        """Change YubiHSM Auth management key

        :param management_key: The current management key.
        :param new_management_key: The new management key.
        """

        self._native.put_management_key(management_key, new_management_key)
        logger.info("New management key set")

    def get_management_key_retries(self) -> int:
        """Get retries remaining for Management key"""

        return self._native.get_management_key_retries()

    def calculate_session_keys_symmetric(
        self,
        label: str,
        context: bytes,
        credential_password: bytes | str,
        card_crypto: bytes | None = None,
    ) -> SessionKeys:
        """Calculate session keys from a symmetric YubiHSM Auth credential.

        :param label: The label of the credential.
        :param context: The context (host challenge + hsm challenge).
        :param credential_password: The password used to protect
            access to the credential.
        :param card_crypto: The card cryptogram.
        """

        pw = _parse_credential_password(credential_password)
        result = self._native.calculate_session_keys_symmetric(
            label, context, pw, card_crypto
        )
        return SessionKeys(
            key_senc=bytes(result[0]),
            key_smac=bytes(result[1]),
            key_srmac=bytes(result[2]),
        )

    def calculate_session_keys_asymmetric(
        self,
        label: str,
        context: bytes,
        public_key: ec.EllipticCurvePublicKey,
        credential_password: bytes | str,
        card_crypto: bytes,
    ) -> SessionKeys:
        """Calculate session keys from an asymmetric YubiHSM Auth credential.

        :param label: The label of the credential.
        :param context: The context (EPK.OCE + EPK.SD).
        :param public_key: The YubiHSM device's public key.
        :param credential_password: The password used to protect
            access to the credential.
        :param card_crypto: The card cryptogram.
        """

        require_version(self.version, (5, 6, 0))
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("Unsupported curve")

        numbers = public_key.public_numbers()
        public_key_data = (
            struct.pack("!B", 4)
            + int.to_bytes(numbers.x, public_key.key_size // 8, "big")
            + int.to_bytes(numbers.y, public_key.key_size // 8, "big")
        )

        pw = _parse_credential_password(credential_password)
        result = self._native.calculate_session_keys_asymmetric(
            label, context, public_key_data, pw, card_crypto
        )
        return SessionKeys(
            key_senc=bytes(result[0]),
            key_smac=bytes(result[1]),
            key_srmac=bytes(result[2]),
        )

    def get_challenge(
        self, label: str, credential_password: bytes | str | None = None
    ) -> bytes:
        """Get the Host Challenge.

        For symmetric credentials this is Host Challenge, a random 8 byte value.
        For asymmetric credentials this is EPK-OCE.

        :param label: The label of the credential.
        :param credential_password: The password used to protect access to the
            credential, needed for asymmetric credentials.
        """
        require_version(self.version, (5, 6, 0))

        pw: bytes | None = None
        if credential_password is not None:
            pw = _parse_credential_password(credential_password)
        return bytes(self._native.get_challenge(label, pw))
