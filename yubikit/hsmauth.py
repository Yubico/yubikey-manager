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

from .core import (
    int2bytes,
    bytes2int,
    require_version,
    Version,
    Tlv,
    InvalidPinError,
)
from .core.smartcard import AID, SmartCardConnection, SmartCardProtocol, ApduError, SW

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec


from functools import total_ordering
from enum import IntEnum, unique
from dataclasses import dataclass
from typing import Optional, List, Union, Tuple, NamedTuple
import struct

import logging

logger = logging.getLogger(__name__)


# TLV tags for credential data
TAG_LABEL = 0x71
TAG_LABEL_LIST = 0x72
TAG_CREDENTIAL_PASSWORD = 0x73
TAG_ALGORITHM = 0x74
TAG_KEY_ENC = 0x75
TAG_KEY_MAC = 0x76
TAG_CONTEXT = 0x77
TAG_RESPONSE = 0x78
TAG_VERSION = 0x79
TAG_TOUCH = 0x7A
TAG_MANAGEMENT_KEY = 0x7B
TAG_PUBLIC_KEY = 0x7C
TAG_PRIVATE_KEY = 0x7D

# Instruction bytes for commands
INS_PUT = 0x01
INS_DELETE = 0x02
INS_CALCULATE = 0x03
INS_GET_CHALLENGE = 0x04
INS_LIST = 0x05
INS_RESET = 0x06
INS_GET_VERSION = 0x07
INS_PUT_MANAGEMENT_KEY = 0x08
INS_GET_MANAGEMENT_KEY_RETRIES = 0x09
INS_GET_PUBLIC_KEY = 0x0A

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
    def key_len(self):
        if self.name.startswith("AES128"):
            return 16
        elif self.name.startswith("EC_P256"):
            return 32

    @property
    def pubkey_len(self):
        if self.name.startswith("EC_P256"):
            return 64


def _parse_credential_password(credential_password: Union[bytes, str]) -> bytes:
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


def _parse_select(response):
    data = Tlv.unpack(TAG_VERSION, response)
    return Version.from_bytes(data)


def _password_to_key(password: str) -> Tuple[bytes, bytes]:
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


def _retries_from_sw(sw):
    if sw & 0xFFF0 == SW.VERIFY_FAIL_NO_RETRY:
        return sw & ~0xFFF0
    return None


@total_ordering
@dataclass(order=False, frozen=True)
class Credential:
    """A YubiHSM Auth credential object."""

    label: str
    algorithm: ALGORITHM
    counter: int
    touch_required: Optional[bool]

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

    @classmethod
    def parse(cls, response: bytes) -> "SessionKeys":
        key_senc = response[:16]
        key_smac = response[16:32]
        key_srmac = response[32:48]

        return cls(
            key_senc=key_senc,
            key_smac=key_smac,
            key_srmac=key_srmac,
        )


class HsmAuthSession:
    """A session with the YubiHSM Auth application."""

    def __init__(self, connection: SmartCardConnection) -> None:
        self.protocol = SmartCardProtocol(connection)
        self._version = _parse_select(self.protocol.select(AID.HSMAUTH))

    @property
    def version(self) -> Version:
        """The YubiHSM Auth application version."""
        return self._version

    def reset(self) -> None:
        """Perform a factory reset on the YubiHSM Auth application."""
        self.protocol.send_apdu(0, INS_RESET, 0xDE, 0xAD)
        logger.info("YubiHSM Auth application data reset performed")

    def list_credentials(self) -> List[Credential]:
        """List YubiHSM Auth credentials on YubiKey"""

        creds = []
        for tlv in Tlv.parse_list(self.protocol.send_apdu(0, INS_LIST, 0, 0)):
            data = Tlv.unpack(TAG_LABEL_LIST, tlv)
            algorithm = ALGORITHM(data[0])
            touch_required = bool(data[1])
            label_length = tlv.length - 3
            label = data[2 : 2 + label_length].decode()
            counter = data[-1]

            creds.append(Credential(label, algorithm, counter, touch_required))
        return creds

    def _put_credential(
        self,
        management_key: bytes,
        label: str,
        key: bytes,
        algorithm: ALGORITHM,
        credential_password: Union[bytes, str],
        touch_required: bool = False,
    ) -> Credential:
        if len(management_key) != MANAGEMENT_KEY_LEN:
            raise ValueError(
                "Management key must be %d bytes long" % MANAGEMENT_KEY_LEN
            )

        data = (
            Tlv(TAG_MANAGEMENT_KEY, management_key)
            + Tlv(TAG_LABEL, _parse_label(label))
            + Tlv(TAG_ALGORITHM, int2bytes(algorithm))
        )

        if algorithm == ALGORITHM.AES128_YUBICO_AUTHENTICATION:
            data += Tlv(TAG_KEY_ENC, key[:16]) + Tlv(TAG_KEY_MAC, key[16:])
        elif algorithm == ALGORITHM.EC_P256_YUBICO_AUTHENTICATION:
            data += Tlv(TAG_PRIVATE_KEY, key)

        data += Tlv(
            TAG_CREDENTIAL_PASSWORD, _parse_credential_password(credential_password)
        )

        if touch_required:
            data += Tlv(TAG_TOUCH, int2bytes(1))
        else:
            data += Tlv(TAG_TOUCH, int2bytes(0))

        logger.debug(
            f"Importing YubiHSM Auth credential (label={label}, algo={algorithm}, "
            f"touch_required={touch_required})"
        )
        try:
            self.protocol.send_apdu(0, INS_PUT, 0, 0, data)
            logger.info("Credential imported")
        except ApduError as e:
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            raise InvalidPinError(
                attempts_remaining=retries,
                message=f"Invalid management key, {retries} attempts remaining",
            )

        return Credential(label, algorithm, INITIAL_RETRY_COUNTER, touch_required)

    def put_credential_symmetric(
        self,
        management_key: bytes,
        label: str,
        key_enc: bytes,
        key_mac: bytes,
        credential_password: Union[bytes, str],
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

        aes128_key_len = ALGORITHM.AES128_YUBICO_AUTHENTICATION.key_len
        if len(key_enc) != aes128_key_len or len(key_mac) != aes128_key_len:
            raise ValueError(
                "Encryption and MAC key must be %d bytes long", aes128_key_len
            )

        return self._put_credential(
            management_key,
            label,
            key_enc + key_mac,
            ALGORITHM.AES128_YUBICO_AUTHENTICATION,
            credential_password,
            touch_required,
        )

    def put_credential_derived(
        self,
        management_key: bytes,
        label: str,
        derivation_password: str,
        credential_password: Union[bytes, str],
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

        key_enc, key_mac = _password_to_key(derivation_password)

        return self.put_credential_symmetric(
            management_key, label, key_enc, key_mac, credential_password, touch_required
        )

    def put_credential_asymmetric(
        self,
        management_key: bytes,
        label: str,
        private_key: ec.EllipticCurvePrivateKeyWithSerialization,
        credential_password: Union[bytes, str],
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

        return self._put_credential(
            management_key,
            label,
            int2bytes(numbers.private_value, ln),
            ALGORITHM.EC_P256_YUBICO_AUTHENTICATION,
            credential_password,
            touch_required,
        )

    def generate_credential_asymmetric(
        self,
        management_key: bytes,
        label: str,
        credential_password: Union[bytes, str],
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
        return self._put_credential(
            management_key,
            label,
            b"",  # Empty byte will generate key
            ALGORITHM.EC_P256_YUBICO_AUTHENTICATION,
            credential_password,
            touch_required,
        )

    def get_public_key(self, label: str) -> ec.EllipticCurvePublicKey:
        """Get the public key for an asymmetric credential.

        This will return the long-term public key "PK-OCE" for an
        asymmetric credential.

        :param label: The label of the credential.
        """
        require_version(self.version, (5, 6, 0))
        data = Tlv(TAG_LABEL, _parse_label(label))
        res = self.protocol.send_apdu(0, INS_GET_PUBLIC_KEY, 0, 0, data)

        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), res)

    def delete_credential(self, management_key: bytes, label: str) -> None:
        """Delete a YubiHSM Auth credential.

        :param management_key: The management key.
        :param label: The label of the credential.
        """

        if len(management_key) != MANAGEMENT_KEY_LEN:
            raise ValueError(
                "Management key must be %d bytes long" % MANAGEMENT_KEY_LEN
            )

        data = Tlv(TAG_MANAGEMENT_KEY, management_key) + Tlv(
            TAG_LABEL, _parse_label(label)
        )

        try:
            self.protocol.send_apdu(0, INS_DELETE, 0, 0, data)
            logger.info("Credential deleted")
        except ApduError as e:
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            raise InvalidPinError(
                attempts_remaining=retries,
                message=f"Invalid management key, {retries} attempts remaining",
            )

    def put_management_key(
        self,
        management_key: bytes,
        new_management_key: bytes,
    ) -> None:
        """Change YubiHSM Auth management key

        :param management_key: The current management key.
        :param new_management_key: The new management key.
        """

        if (
            len(management_key) != MANAGEMENT_KEY_LEN
            or len(new_management_key) != MANAGEMENT_KEY_LEN
        ):
            raise ValueError(
                "Management key must be %d bytes long" % MANAGEMENT_KEY_LEN
            )

        data = Tlv(TAG_MANAGEMENT_KEY, management_key) + Tlv(
            TAG_MANAGEMENT_KEY, new_management_key
        )

        try:
            self.protocol.send_apdu(0, INS_PUT_MANAGEMENT_KEY, 0, 0, data)
            logger.info("New management key set")
        except ApduError as e:
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            raise InvalidPinError(
                attempts_remaining=retries,
                message=f"Invalid management key, {retries} attempts remaining",
            )

    def get_management_key_retries(self) -> int:
        """Get retries remaining for Management key"""

        res = self.protocol.send_apdu(0, INS_GET_MANAGEMENT_KEY_RETRIES, 0, 0)
        return bytes2int(res)

    def _calculate_session_keys(
        self,
        label: str,
        context: bytes,
        credential_password: Union[bytes, str],
        card_crypto: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
    ) -> bytes:
        data = Tlv(TAG_LABEL, _parse_label(label)) + Tlv(TAG_CONTEXT, context)

        if public_key:
            data += Tlv(TAG_PUBLIC_KEY, public_key)

        if card_crypto:
            data += Tlv(TAG_RESPONSE, card_crypto)

        data += Tlv(
            TAG_CREDENTIAL_PASSWORD, _parse_credential_password(credential_password)
        )

        try:
            res = self.protocol.send_apdu(0, INS_CALCULATE, 0, 0, data)
            logger.info("Session keys calculated")
        except ApduError as e:
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            raise InvalidPinError(
                attempts_remaining=retries,
                message=f"Invalid credential password, {retries} attempts remaining",
            )

        return res

    def calculate_session_keys_symmetric(
        self,
        label: str,
        context: bytes,
        credential_password: Union[bytes, str],
        card_crypto: Optional[bytes] = None,
    ) -> SessionKeys:
        """Calculate session keys from a symmetric YubiHSM Auth credential.

        :param label: The label of the credential.
        :param context: The context (host challenge + hsm challenge).
        :param credential_password: The password used to protect
            access to the credential.
        :param card_crypto: The card cryptogram.
        """

        return SessionKeys.parse(
            self._calculate_session_keys(
                label=label,
                context=context,
                credential_password=credential_password,
                card_crypto=card_crypto,
            )
        )

    def calculate_session_keys_asymmetric(
        self,
        label: str,
        context: bytes,
        public_key: ec.EllipticCurvePublicKey,
        credential_password: Union[bytes, str],
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

        return SessionKeys.parse(
            self._calculate_session_keys(
                label=label,
                context=context,
                credential_password=credential_password,
                card_crypto=card_crypto,
                public_key=public_key_data,
            )
        )

    def get_challenge(self, label: str) -> bytes:
        """Get the Host Challenge.

        For symmetric credentials this is Host Challenge, a random
        8 byte value. For asymmetric credentials this is EPK-OCE.

        :param label: The label of the credential.
        """
        require_version(self.version, (5, 6, 0))
        data = Tlv(TAG_LABEL, _parse_label(label))
        return self.protocol.send_apdu(0, INS_GET_CHALLENGE, 0, 0, data)
