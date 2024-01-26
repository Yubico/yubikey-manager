# Copyright (c) 2020 Yubico AB
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
    require_version as _require_version,
    int2bytes,
    bytes2int,
    Version,
    Tlv,
    NotSupportedError,
    BadResponseError,
    InvalidPinError,
)
from .core.smartcard import (
    SW,
    AID,
    ApduError,
    ApduFormat,
    SmartCardConnection,
    SmartCardProtocol,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

from dataclasses import dataclass
from enum import Enum, IntEnum, unique
from typing import Optional, Union, Type, cast

import logging
import gzip
import os
import re


logger = logging.getLogger(__name__)


@unique
class ALGORITHM(str, Enum):
    EC = "ec"
    RSA = "rsa"


# Don't treat pre 1.0 versions as "developer builds".
def require_version(my_version: Version, *args, **kwargs):
    if my_version <= (0, 1, 4):  # Last pre 1.0 release of ykneo-piv
        my_version = Version(1, 0, 0)
    _require_version(my_version, *args, **kwargs)


@unique
class KEY_TYPE(IntEnum):
    RSA1024 = 0x06
    RSA2048 = 0x07
    RSA3072 = 0x05
    RSA4096 = 0x16
    ECCP256 = 0x11
    ECCP384 = 0x14
    ED25519 = 0xE0
    X25519 = 0xE1

    def __str__(self):
        return self.name

    @property
    def algorithm(self):
        return ALGORITHM.RSA if self.name.startswith("RSA") else ALGORITHM.EC

    @property
    def bit_len(self):
        if self in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
            return 256
        match = re.search(r"\d+$", self.name)
        if match:
            return int(match.group())
        raise ValueError("No bit_len")

    @classmethod
    def from_public_key(cls, key):
        if isinstance(key, rsa.RSAPublicKey):
            try:
                return getattr(cls, "RSA%d" % key.key_size)
            except AttributeError:
                raise ValueError("Unsupported RSA key size: %d" % key.key_size)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            curve_name = key.curve.name
            if curve_name == "secp256r1":
                return cls.ECCP256
            elif curve_name == "secp384r1":
                return cls.ECCP384
            raise ValueError(f"Unsupported EC curve: {curve_name}")
        elif isinstance(key, ed25519.Ed25519PublicKey):
            return cls.ED25519
        elif isinstance(key, x25519.X25519PublicKey):
            return cls.X25519
        raise ValueError(f"Unsupported key type: {type(key).__name__}")


@unique
class MANAGEMENT_KEY_TYPE(IntEnum):
    TDES = 0x03
    AES128 = 0x08
    AES192 = 0x0A
    AES256 = 0x0C

    @property
    def key_len(self):
        if self.name == "TDES":
            return 24
        # AES
        return int(self.name[3:]) // 8

    @property
    def challenge_len(self):
        if self.name == "TDES":
            return 8
        return 16


def _parse_management_key(key_type, management_key):
    if key_type == MANAGEMENT_KEY_TYPE.TDES:
        return algorithms.TripleDES(management_key)
    else:
        return algorithms.AES(management_key)


# The following slots are special, we don't include it in SLOT below
SLOT_CARD_MANAGEMENT = 0x9B
SLOT_OCC_AUTH = 0x96


@unique
class SLOT(IntEnum):
    AUTHENTICATION = 0x9A
    SIGNATURE = 0x9C
    KEY_MANAGEMENT = 0x9D
    CARD_AUTH = 0x9E

    RETIRED1 = 0x82
    RETIRED2 = 0x83
    RETIRED3 = 0x84
    RETIRED4 = 0x85
    RETIRED5 = 0x86
    RETIRED6 = 0x87
    RETIRED7 = 0x88
    RETIRED8 = 0x89
    RETIRED9 = 0x8A
    RETIRED10 = 0x8B
    RETIRED11 = 0x8C
    RETIRED12 = 0x8D
    RETIRED13 = 0x8E
    RETIRED14 = 0x8F
    RETIRED15 = 0x90
    RETIRED16 = 0x91
    RETIRED17 = 0x92
    RETIRED18 = 0x93
    RETIRED19 = 0x94
    RETIRED20 = 0x95

    ATTESTATION = 0xF9

    def __str__(self) -> str:
        return f"{int(self):02X} ({self.name})"


@unique
class OBJECT_ID(IntEnum):
    CAPABILITY = 0x5FC107
    CHUID = 0x5FC102
    AUTHENTICATION = 0x5FC105  # cert for 9a key
    FINGERPRINTS = 0x5FC103
    SECURITY = 0x5FC106
    FACIAL = 0x5FC108
    PRINTED = 0x5FC109
    SIGNATURE = 0x5FC10A  # cert for 9c key
    KEY_MANAGEMENT = 0x5FC10B  # cert for 9d key
    CARD_AUTH = 0x5FC101  # cert for 9e key
    DISCOVERY = 0x7E
    KEY_HISTORY = 0x5FC10C
    IRIS = 0x5FC121

    RETIRED1 = 0x5FC10D
    RETIRED2 = 0x5FC10E
    RETIRED3 = 0x5FC10F
    RETIRED4 = 0x5FC110
    RETIRED5 = 0x5FC111
    RETIRED6 = 0x5FC112
    RETIRED7 = 0x5FC113
    RETIRED8 = 0x5FC114
    RETIRED9 = 0x5FC115
    RETIRED10 = 0x5FC116
    RETIRED11 = 0x5FC117
    RETIRED12 = 0x5FC118
    RETIRED13 = 0x5FC119
    RETIRED14 = 0x5FC11A
    RETIRED15 = 0x5FC11B
    RETIRED16 = 0x5FC11C
    RETIRED17 = 0x5FC11D
    RETIRED18 = 0x5FC11E
    RETIRED19 = 0x5FC11F
    RETIRED20 = 0x5FC120

    ATTESTATION = 0x5FFF01

    @classmethod
    def from_slot(cls, slot):
        return getattr(cls, SLOT(slot).name)


@unique
class PIN_POLICY(IntEnum):
    DEFAULT = 0x0
    NEVER = 0x1
    ONCE = 0x2
    ALWAYS = 0x3
    MATCH_ONCE = 0x4
    MATCH_ALWAYS = 0x5


@unique
class TOUCH_POLICY(IntEnum):
    DEFAULT = 0x0
    NEVER = 0x1
    ALWAYS = 0x2
    CACHED = 0x3


# 010203040506070801020304050607080102030405060708
DEFAULT_MANAGEMENT_KEY = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08"
    + b"\x01\x02\x03\x04\x05\x06\x07\x08"
    + b"\x01\x02\x03\x04\x05\x06\x07\x08"
)

PIN_LEN = 8
TEMPORARY_PIN_LEN = 16

# Instruction set
INS_VERIFY = 0x20
INS_CHANGE_REFERENCE = 0x24
INS_RESET_RETRY = 0x2C
INS_GENERATE_ASYMMETRIC = 0x47
INS_AUTHENTICATE = 0x87
INS_GET_DATA = 0xCB
INS_PUT_DATA = 0xDB
INS_MOVE_KEY = 0xF6
INS_GET_METADATA = 0xF7
INS_ATTEST = 0xF9
INS_SET_PIN_RETRIES = 0xFA
INS_RESET = 0xFB
INS_GET_VERSION = 0xFD
INS_IMPORT_KEY = 0xFE
INS_SET_MGMKEY = 0xFF

# Tags for parsing responses and preparing requests
TAG_AUTH_WITNESS = 0x80
TAG_AUTH_CHALLENGE = 0x81
TAG_AUTH_RESPONSE = 0x82
TAG_AUTH_EXPONENTIATION = 0x85
TAG_GEN_ALGORITHM = 0x80
TAG_OBJ_DATA = 0x53
TAG_OBJ_ID = 0x5C
TAG_CERTIFICATE = 0x70
TAG_CERT_INFO = 0x71
TAG_DYN_AUTH = 0x7C
TAG_LRC = 0xFE
TAG_PIN_POLICY = 0xAA
TAG_TOUCH_POLICY = 0xAB

# Metadata tags
TAG_METADATA_ALGO = 0x01
TAG_METADATA_POLICY = 0x02
TAG_METADATA_ORIGIN = 0x03
TAG_METADATA_PUBLIC_KEY = 0x04
TAG_METADATA_IS_DEFAULT = 0x05
TAG_METADATA_RETRIES = 0x06
TAG_METADATA_BIO_CONFIGURED = 0x07
TAG_METADATA_TEMPORARY_PIN = 0x08

ORIGIN_GENERATED = 1
ORIGIN_IMPORTED = 2

INDEX_PIN_POLICY = 0
INDEX_TOUCH_POLICY = 1
INDEX_RETRIES_TOTAL = 0
INDEX_RETRIES_REMAINING = 1

PIN_P2 = 0x80
PUK_P2 = 0x81
UV_P2 = 0x96


def _pin_bytes(pin):
    pin = pin.encode()
    if len(pin) > PIN_LEN:
        raise ValueError("PIN/PUK must be no longer than 8 bytes")
    return pin.ljust(PIN_LEN, b"\xff")


def _retries_from_sw(sw):
    if sw == SW.AUTH_METHOD_BLOCKED:
        return 0
    if sw & 0xFFF0 == 0x63C0:
        return sw & 0x0F
    elif sw & 0xFF00 == 0x6300:
        return sw & 0xFF
    return None


@dataclass
class PinMetadata:
    default_value: bool
    total_attempts: int
    attempts_remaining: int


@dataclass
class ManagementKeyMetadata:
    key_type: MANAGEMENT_KEY_TYPE
    default_value: bool
    touch_policy: TOUCH_POLICY


@dataclass
class SlotMetadata:
    key_type: KEY_TYPE
    pin_policy: PIN_POLICY
    touch_policy: TOUCH_POLICY
    generated: bool
    public_key_encoded: bytes

    @property
    def public_key(self):
        return _parse_device_public_key(self.key_type, self.public_key_encoded)


@dataclass
class BioMetadata:
    configured: bool
    attempts_remaining: int
    temporary_pin: bool


def _pad_message(key_type, message, hash_algorithm, padding):
    if key_type in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
        return message
    if key_type.algorithm == ALGORITHM.EC:
        if isinstance(hash_algorithm, Prehashed):
            hashed = message
        else:
            h = hashes.Hash(hash_algorithm, default_backend())
            h.update(message)
            hashed = h.finalize()
        byte_len = key_type.bit_len // 8
        if len(hashed) < byte_len:
            return hashed.rjust(byte_len // 8, b"\0")
        return hashed[:byte_len]
    elif key_type.algorithm == ALGORITHM.RSA:
        # Sign with a dummy key, then encrypt the signature to get the padded message
        e = 65537
        dummy = rsa.generate_private_key(e, key_type.bit_len, default_backend())
        signature = dummy.sign(message, padding, hash_algorithm)
        # Raw (textbook) RSA encrypt
        n = dummy.public_key().public_numbers().n
        return int2bytes(pow(bytes2int(signature), e, n), key_type.bit_len // 8)


def _unpad_message(padded, padding):
    e = 65537
    dummy = rsa.generate_private_key(e, len(padded) * 8, default_backend())
    # Raw (textbook) RSA encrypt
    n = dummy.public_key().public_numbers().n
    encrypted = int2bytes(pow(bytes2int(padded), e, n), len(padded))
    return dummy.decrypt(encrypted, padding)


def check_key_support(
    version: Version,
    key_type: KEY_TYPE,
    pin_policy: PIN_POLICY,
    touch_policy: TOUCH_POLICY,
    generate: bool = True,
) -> None:
    """Check if a key type is supported by a specific YubiKey firmware version.

    This method will return None if the key (with PIN and touch policies) is supported,
    or it will raise a NotSupportedError if it is not.
    """
    if version[0] == 0 and version > (0, 1, 3):
        return  # Development build, skip version checks

    if version < (4, 0, 0):
        if key_type == KEY_TYPE.ECCP384:
            raise NotSupportedError("ECCP384 requires YubiKey 4 or later")
        if touch_policy != TOUCH_POLICY.DEFAULT or pin_policy != PIN_POLICY.DEFAULT:
            raise NotSupportedError("PIN/Touch policy requires YubiKey 4 or later")

    if version < (4, 3, 0) and touch_policy == TOUCH_POLICY.CACHED:
        raise NotSupportedError("Cached touch policy requires YubiKey 4.3 or later")

    # ROCA
    if (4, 2, 0) <= version < (4, 3, 5):
        if generate and key_type.algorithm == ALGORITHM.RSA:
            raise NotSupportedError("RSA key generation not supported on this YubiKey")

    # FIPS
    if (4, 4, 0) <= version < (4, 5, 0):
        if key_type == KEY_TYPE.RSA1024:
            raise NotSupportedError("RSA 1024 not supported on YubiKey FIPS")
        if pin_policy == PIN_POLICY.NEVER:
            raise NotSupportedError("PIN_POLICY.NEVER not allowed on YubiKey FIPS")

    # New key types
    if version < (5, 7, 0) and key_type in (
        KEY_TYPE.RSA3072,
        KEY_TYPE.RSA4096,
        KEY_TYPE.ED25519,
        KEY_TYPE.X25519,
    ):
        raise NotSupportedError(f"{key_type} requires YubiKey 5.7 or later")

    # TODO: Detect Bio capabilities
    if version < () and pin_policy in (PIN_POLICY.MATCH_ONCE, PIN_POLICY.MATCH_ALWAYS):
        raise NotSupportedError(
            "Biometric match PIN policy requires YubiKey 5.6 or later"
        )


def _parse_device_public_key(key_type, encoded):
    data = Tlv.parse_dict(encoded)
    if key_type.algorithm == ALGORITHM.RSA:
        modulus = bytes2int(data[0x81])
        exponent = bytes2int(data[0x82])
        return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
    elif key_type == KEY_TYPE.ED25519:
        return ed25519.Ed25519PublicKey.from_public_bytes(data[0x86])
    elif key_type == KEY_TYPE.X25519:
        return x25519.X25519PublicKey.from_public_bytes(data[0x86])
    else:
        if key_type == KEY_TYPE.ECCP256:
            curve: Type[ec.EllipticCurve] = ec.SECP256R1
        else:
            curve = ec.SECP384R1

        return ec.EllipticCurvePublicKey.from_encoded_point(curve(), data[0x86])


class PivSession:
    """A session with the PIV application."""

    def __init__(self, connection: SmartCardConnection):
        self.protocol = SmartCardProtocol(connection)
        self.protocol.select(AID.PIV)
        self._version = Version.from_bytes(
            self.protocol.send_apdu(0, INS_GET_VERSION, 0, 0)
        )
        self.protocol.enable_touch_workaround(self.version)
        if self.version >= (4, 0, 0):
            self.protocol.apdu_format = ApduFormat.EXTENDED
        self._current_pin_retries = 3
        self._max_pin_retries = 3
        logger.debug(f"PIV session initialized (version={self.version})")

    @property
    def version(self) -> Version:
        return self._version

    def reset(self) -> None:
        logger.debug("Preparing PIV reset")

        try:
            if self.get_bio_metadata().configured:
                raise ValueError(
                    "Cannot perform PIV reset when biometrics are configured"
                )
        except NotSupportedError:
            pass

        # Block PIN
        logger.debug("Verify PIN with invalid attempts until blocked")
        counter = self.get_pin_attempts()
        while counter > 0:
            try:
                self.verify_pin("")
            except InvalidPinError as e:
                counter = e.attempts_remaining
        logger.debug("PIN is blocked")

        # Block PUK
        logger.debug("Verify PUK with invalid attempts until blocked")
        try:
            counter = self.get_puk_metadata().attempts_remaining
        except NotSupportedError:
            counter = 1
        while counter > 0:
            try:
                self._change_reference(INS_RESET_RETRY, PIN_P2, "", "")
            except InvalidPinError as e:
                counter = e.attempts_remaining
        logger.debug("PUK is blocked")

        # Reset
        logger.debug("Sending reset")
        self.protocol.send_apdu(0, INS_RESET, 0, 0)
        self._current_pin_retries = 3
        self._max_pin_retries = 3

        logger.info("PIV application data reset performed")

    def authenticate(
        self, key_type: MANAGEMENT_KEY_TYPE, management_key: bytes
    ) -> None:
        """Authenticate to PIV with management key.

        :param key_type: The management key type.
        :param management_key: The management key in raw bytes.
        """
        key_type = MANAGEMENT_KEY_TYPE(key_type)
        logger.debug(f"Authenticating with key type: {key_type}")
        response = self.protocol.send_apdu(
            0,
            INS_AUTHENTICATE,
            key_type,
            SLOT_CARD_MANAGEMENT,
            Tlv(TAG_DYN_AUTH, Tlv(TAG_AUTH_WITNESS)),
        )
        witness = Tlv.unpack(TAG_AUTH_WITNESS, Tlv.unpack(TAG_DYN_AUTH, response))
        challenge = os.urandom(key_type.challenge_len)

        backend = default_backend()
        cipher_key = _parse_management_key(key_type, management_key)
        cipher = Cipher(cipher_key, modes.ECB(), backend)  # nosec
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(witness) + decryptor.finalize()

        response = self.protocol.send_apdu(
            0,
            INS_AUTHENTICATE,
            key_type,
            SLOT_CARD_MANAGEMENT,
            Tlv(
                TAG_DYN_AUTH,
                Tlv(TAG_AUTH_WITNESS, decrypted) + Tlv(TAG_AUTH_CHALLENGE, challenge),
            ),
        )
        encrypted = Tlv.unpack(TAG_AUTH_RESPONSE, Tlv.unpack(TAG_DYN_AUTH, response))
        encryptor = cipher.encryptor()
        expected = encryptor.update(challenge) + encryptor.finalize()
        if not bytes_eq(expected, encrypted):
            raise BadResponseError("Device response is incorrect")

    def set_management_key(
        self,
        key_type: MANAGEMENT_KEY_TYPE,
        management_key: bytes,
        require_touch: bool = False,
    ) -> None:
        """Set a new management key.

        :param key_type: The management key type.
        :param management_key: The management key in raw bytes.
        :param require_touch: The touch policy.
        """
        key_type = MANAGEMENT_KEY_TYPE(key_type)
        logger.debug(f"Setting management key of type: {key_type}")

        if key_type != MANAGEMENT_KEY_TYPE.TDES:
            require_version(self.version, (5, 4, 0))
        if len(management_key) != key_type.key_len:
            raise ValueError("Management key must be %d bytes" % key_type.key_len)

        self.protocol.send_apdu(
            0,
            INS_SET_MGMKEY,
            0xFF,
            0xFE if require_touch else 0xFF,
            int2bytes(key_type) + Tlv(SLOT_CARD_MANAGEMENT, management_key),
        )
        logger.info("Management key set")

    def verify_pin(self, pin: str) -> None:
        """Verify the PIN.

        :param pin: The PIN.
        """
        logger.debug("Verifying PIN")
        try:
            self.protocol.send_apdu(0, INS_VERIFY, 0, PIN_P2, _pin_bytes(pin))
            self._current_pin_retries = self._max_pin_retries
        except ApduError as e:
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            self._current_pin_retries = retries
            raise InvalidPinError(retries)

    def verify_uv(self) -> bytes:
        logger.debug("Verifying UV")
        try:
            return self.protocol.send_apdu(0, INS_VERIFY, 0, SLOT_OCC_AUTH)
        except ApduError as e:
            if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
                raise NotSupportedError(
                    "Biometric verification not supported by this YuibKey"
                )
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            raise InvalidPinError(
                retries, f"Fingerprint mismatch, {retries} attempts remaining"
            )

    def verify_temporary_pin(self, pin: bytes) -> None:
        logger.debug("Verifying temporary PIN")
        if len(pin) != TEMPORARY_PIN_LEN:
            raise ValueError(f"Temporary PIN must be exactly {TEMPORARY_PIN_LEN} bytes")
        try:
            self.protocol.send_apdu(0, INS_VERIFY, 0, SLOT_OCC_AUTH, Tlv(1, pin))
        except ApduError as e:
            if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
                raise NotSupportedError(
                    "Biometric verification not supported by this YuibKey"
                )
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            raise InvalidPinError(
                retries, f"Invalid temporary PIN, {retries} attempts remaining"
            )

    def get_pin_attempts(self) -> int:
        """Get remaining PIN attempts."""
        logger.debug("Getting PIN attempts")
        try:
            return self.get_pin_metadata().attempts_remaining
        except NotSupportedError:
            try:
                self.protocol.send_apdu(0, INS_VERIFY, 0, PIN_P2)
                # Already verified, no way to know true count
                logger.debug("Using cached value, may be incorrect.")
                return self._current_pin_retries
            except ApduError as e:
                retries = _retries_from_sw(e.sw)
                if retries is None:
                    raise
                self._current_pin_retries = retries
                logger.debug("Using value from empty verify")
                return retries

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        """Change the PIN.

        :param old_pin: The current PIN.
        :param new_pin: The new PIN.
        """
        logger.debug("Changing PIN")
        self._change_reference(INS_CHANGE_REFERENCE, PIN_P2, old_pin, new_pin)
        logger.info("New PIN set")

    def change_puk(self, old_puk: str, new_puk: str) -> None:
        """Change the PUK.

        :param old_puk: The current PUK.
        :param new_puk: The new PUK.
        """
        logger.debug("Changing PUK")
        self._change_reference(INS_CHANGE_REFERENCE, PUK_P2, old_puk, new_puk)
        logger.info("New PUK set")

    def unblock_pin(self, puk: str, new_pin: str) -> None:
        """Reset PIN with PUK.

        :param puk: The PUK.
        :param new_pin: The new PIN.
        """
        logger.debug("Using PUK to set new PIN")
        self._change_reference(INS_RESET_RETRY, PIN_P2, puk, new_pin)
        logger.info("New PIN set")

    def set_pin_attempts(self, pin_attempts: int, puk_attempts: int) -> None:
        """Set PIN retries for PIN and PUK.

        Both PIN and PUK will be reset to default values when this is executed.

        Requires authentication with management key and PIN verification.

        :param pin_attempts: The PIN attempts.
        :param puk_attempts: The PUK attempts.
        """
        logger.debug(f"Setting PIN/PUK attempts ({pin_attempts}, {puk_attempts})")
        try:
            self.protocol.send_apdu(0, INS_SET_PIN_RETRIES, pin_attempts, puk_attempts)
            self._max_pin_retries = pin_attempts
            self._current_pin_retries = pin_attempts
            logger.info("PIN/PUK attempts set")
        except ApduError as e:
            if e.sw == SW.INVALID_INSTRUCTION:
                raise NotSupportedError(
                    "Setting PIN attempts not supported on this YubiKey"
                )
            raise

    def get_pin_metadata(self) -> PinMetadata:
        """Get PIN metadata."""
        logger.debug("Getting PIN metadata")
        return self._get_pin_puk_metadata(PIN_P2)

    def get_puk_metadata(self) -> PinMetadata:
        """Get PUK metadata."""
        logger.debug("Getting PUK metadata")
        return self._get_pin_puk_metadata(PUK_P2)

    def get_management_key_metadata(self) -> ManagementKeyMetadata:
        """Get management key metadata."""
        logger.debug("Getting management key metadata")
        require_version(self.version, (5, 3, 0))
        data = Tlv.parse_dict(
            self.protocol.send_apdu(0, INS_GET_METADATA, 0, SLOT_CARD_MANAGEMENT)
        )
        policy = data[TAG_METADATA_POLICY]
        return ManagementKeyMetadata(
            MANAGEMENT_KEY_TYPE(data.get(TAG_METADATA_ALGO, b"\x03")[0]),
            data[TAG_METADATA_IS_DEFAULT] != b"\0",
            TOUCH_POLICY(policy[INDEX_TOUCH_POLICY]),
        )

    def get_slot_metadata(self, slot: SLOT) -> SlotMetadata:
        """Get slot metadata.

        :param slot: The slot to get metadata from.
        """
        slot = SLOT(slot)
        logger.debug(f"Getting metadata for slot {slot}")
        require_version(self.version, (5, 3, 0))
        data = Tlv.parse_dict(self.protocol.send_apdu(0, INS_GET_METADATA, 0, slot))
        policy = data[TAG_METADATA_POLICY]
        return SlotMetadata(
            KEY_TYPE(data[TAG_METADATA_ALGO][0]),
            PIN_POLICY(policy[INDEX_PIN_POLICY]),
            TOUCH_POLICY(policy[INDEX_TOUCH_POLICY]),
            data[TAG_METADATA_ORIGIN][0] == ORIGIN_GENERATED,
            data[TAG_METADATA_PUBLIC_KEY],
        )

    def get_bio_metadata(self) -> BioMetadata:
        logger.debug("Getting bio metadata")
        try:
            data = Tlv.parse_dict(
                self.protocol.send_apdu(0, INS_GET_METADATA, 0, SLOT_OCC_AUTH)
            )
        except ApduError as e:
            if e.sw in (SW.REFERENCE_DATA_NOT_FOUND, SW.INVALID_INSTRUCTION):
                raise NotSupportedError(
                    "Biometric verification not supported by this YuibKey"
                )
            raise
        return BioMetadata(
            1 == data.get(TAG_METADATA_BIO_CONFIGURED, b"\x00")[0],
            data[TAG_METADATA_RETRIES][0],
            1 == data.get(TAG_METADATA_TEMPORARY_PIN, b"\x00")[0],
        )

    def sign(
        self,
        slot: SLOT,
        key_type: KEY_TYPE,
        message: bytes,
        hash_algorithm: hashes.HashAlgorithm,
        padding: Optional[AsymmetricPadding] = None,
    ) -> bytes:
        """Sign message with key.

        Requires PIN verification.

        :param slot: The slot of the key to use.
        :param key_type: The type of the key to sign with.
        :param message: The message to sign.
        :param hash_algorithm: The pre-signature hash algorithm to use.
        :param padding: The pre-signature padding.
        """
        slot = SLOT(slot)
        key_type = KEY_TYPE(key_type)
        logger.debug(
            f"Signing data with key in slot {slot} of type {key_type} using "
            f"hash={hash_algorithm}, padding={padding}"
        )
        padded = _pad_message(key_type, message, hash_algorithm, padding)
        return self._use_private_key(slot, key_type, padded, False)

    def decrypt(
        self, slot: SLOT, cipher_text: bytes, padding: AsymmetricPadding
    ) -> bytes:
        """Decrypt cipher text.

        Requires PIN verification.

        :param slot: The slot.
        :param cipher_text: The cipher text to decrypt.
        :param padding: The padding of the plain text.
        """
        slot = SLOT(slot)
        try:
            key_type = getattr(KEY_TYPE, f"RSA{len(cipher_text) * 8}")
        except AttributeError:
            raise ValueError("Invalid length of ciphertext")
        logger.debug(
            f"Decrypting data with key in slot {slot} of type {key_type} using ",
            f"padding={padding}",
        )
        padded = self._use_private_key(slot, key_type, cipher_text, False)
        return _unpad_message(padded, padding)

    def calculate_secret(
        self,
        slot: SLOT,
        peer_public_key: Union[
            ec.EllipticCurvePrivateKeyWithSerialization, x25519.X25519PublicKey
        ],
    ) -> bytes:
        """Calculate shared secret using ECDH.

        Requires PIN verification.

        :param slot: The slot.
        :param peer_public_key: The peer's public key.
        """
        slot = SLOT(slot)
        key_type = KEY_TYPE.from_public_key(peer_public_key)
        if key_type.algorithm != ALGORITHM.EC:
            raise ValueError("Unsupported key type")
        logger.debug(
            f"Performing key agreement with key in slot {slot} of type {key_type}"
        )
        if key_type == KEY_TYPE.X25519:
            data = peer_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            data = peer_public_key.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
        return self._use_private_key(slot, key_type, data, True)

    def get_object(self, object_id: int) -> bytes:
        """Get object by ID.

        Requires PIN verification for protected objects.

        :param object_id: The object identifier.
        """
        logger.debug(f"Reading data from object slot {hex(object_id)}")
        if object_id == OBJECT_ID.DISCOVERY:
            expected: int = OBJECT_ID.DISCOVERY
        else:
            expected = TAG_OBJ_DATA

        try:
            return Tlv.unpack(
                expected,
                self.protocol.send_apdu(
                    0,
                    INS_GET_DATA,
                    0x3F,
                    0xFF,
                    Tlv(TAG_OBJ_ID, int2bytes(object_id)),
                ),
            )
        except ValueError as e:
            raise BadResponseError("Malformed object data", e)

    def put_object(self, object_id: int, data: Optional[bytes] = None) -> None:
        """Write data to PIV object.

        Requires authentication with management key.

        :param object_id: The object identifier.
        :param data: The object data.
        """
        self.protocol.send_apdu(
            0,
            INS_PUT_DATA,
            0x3F,
            0xFF,
            Tlv(TAG_OBJ_ID, int2bytes(object_id)) + Tlv(TAG_OBJ_DATA, data or b""),
        )
        logger.info(f"Data written to object slot {hex(object_id)}")

    def get_certificate(self, slot: SLOT) -> x509.Certificate:
        """Get certificate from slot.

        :param slot: The slot to get the certificate from.
        """
        slot = SLOT(slot)
        logger.debug(f"Reading certificate in slot {slot}")
        try:
            data = Tlv.parse_dict(self.get_object(OBJECT_ID.from_slot(slot)))
            cert_data = data[TAG_CERTIFICATE]
            cert_info = data[TAG_CERT_INFO][0] if TAG_CERT_INFO in data else 0
        except (ValueError, KeyError):
            raise BadResponseError("Malformed certificate data object")

        if cert_info == 1:
            logger.debug("Certificate is compressed, decompressing...")
            # Compressed certificate
            cert_data = gzip.decompress(cert_data)
        elif cert_info != 0:
            raise NotSupportedError("Unsupported value in CertInfo")

        try:
            return x509.load_der_x509_certificate(cert_data, default_backend())
        except Exception as e:
            raise BadResponseError("Invalid certificate", e)

    def put_certificate(
        self, slot: SLOT, certificate: x509.Certificate, compress: bool = False
    ) -> None:
        """Import certificate to slot.

        Requires authentication with management key.

        :param slot: The slot to import the certificate to.
        :param certificate: The certificate to import.
        :param compress: If the certificate should be compressed or not.
        """
        slot = SLOT(slot)
        logger.debug(f"Storing certificate in slot {slot}")
        cert_data = certificate.public_bytes(Encoding.DER)
        logger.debug(f"Certificate is {len(cert_data)} bytes, compression={compress}")
        if compress:
            cert_info = b"\1"
            cert_data = gzip.compress(cert_data)
            logger.debug(f"Compressed size: {len(cert_data)} bytes")
        else:
            cert_info = b"\0"
        data = (
            Tlv(TAG_CERTIFICATE, cert_data)
            + Tlv(TAG_CERT_INFO, cert_info)
            + Tlv(TAG_LRC)
        )
        self.put_object(OBJECT_ID.from_slot(slot), data)
        logger.info(f"Certificate written to slot {slot}, compression={compress}")

    def delete_certificate(self, slot: SLOT) -> None:
        """Delete certificate.

        Requires authentication with management key.

        :param slot: The slot to delete the certificate from.
        """
        slot = SLOT(slot)
        logger.debug(f"Deleting certificate in slot {slot}")
        self.put_object(OBJECT_ID.from_slot(slot))

    def put_key(
        self,
        slot: SLOT,
        private_key: Union[
            rsa.RSAPrivateKeyWithSerialization,
            ec.EllipticCurvePrivateKeyWithSerialization,
        ],
        pin_policy: PIN_POLICY = PIN_POLICY.DEFAULT,
        touch_policy: TOUCH_POLICY = TOUCH_POLICY.DEFAULT,
    ) -> None:
        """Import a private key to slot.

        Requires authentication with management key.

        :param slot: The slot to import the key to.
        :param private_key: The private key to import.
        :param pin_policy: The PIN policy.
        :param touch_policy: The touch policy.
        """
        slot = SLOT(slot)
        key_type = KEY_TYPE.from_public_key(private_key.public_key())
        check_key_support(self.version, key_type, pin_policy, touch_policy, False)
        ln = key_type.bit_len // 8
        if key_type.algorithm == ALGORITHM.RSA:
            numbers = private_key.private_numbers()
            numbers = cast(rsa.RSAPrivateNumbers, numbers)
            if numbers.public_numbers.e != 65537:
                raise NotSupportedError("RSA exponent must be 65537")
            ln //= 2
            data = (
                Tlv(0x01, int2bytes(numbers.p, ln))
                + Tlv(0x02, int2bytes(numbers.q, ln))
                + Tlv(0x03, int2bytes(numbers.dmp1, ln))
                + Tlv(0x04, int2bytes(numbers.dmq1, ln))
                + Tlv(0x05, int2bytes(numbers.iqmp, ln))
            )
        elif key_type in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
            data = Tlv(
                0x07 if key_type == KEY_TYPE.ED25519 else 0x08,
                private_key.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                ),
            )
        else:
            numbers = private_key.private_numbers()
            numbers = cast(ec.EllipticCurvePrivateNumbers, numbers)
            data = Tlv(0x06, int2bytes(numbers.private_value, ln))
        if pin_policy:
            data += Tlv(TAG_PIN_POLICY, int2bytes(pin_policy))
        if touch_policy:
            data += Tlv(TAG_TOUCH_POLICY, int2bytes(touch_policy))

        logger.debug(
            f"Importing key with pin_policy={pin_policy}, touch_policy={touch_policy}"
        )
        self.protocol.send_apdu(0, INS_IMPORT_KEY, key_type, slot, data)
        logger.info(f"Private key imported in slot {slot} of type {key_type}")
        return key_type

    def generate_key(
        self,
        slot: SLOT,
        key_type: KEY_TYPE,
        pin_policy: PIN_POLICY = PIN_POLICY.DEFAULT,
        touch_policy: TOUCH_POLICY = TOUCH_POLICY.DEFAULT,
    ) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        """Generate private key in slot.

        Requires authentication with management key.

        :param slot: The slot to generate the private key in.
        :param key_type: The key type.
        :param pin_policy: The PIN policy.
        :param touch_policy: The touch policy.
        """
        slot = SLOT(slot)
        key_type = KEY_TYPE(key_type)
        check_key_support(self.version, key_type, pin_policy, touch_policy, True)
        data: bytes = Tlv(TAG_GEN_ALGORITHM, int2bytes(key_type))
        if pin_policy:
            data += Tlv(TAG_PIN_POLICY, int2bytes(pin_policy))
        if touch_policy:
            data += Tlv(TAG_TOUCH_POLICY, int2bytes(touch_policy))

        logger.debug(
            f"Generating key with pin_policy={pin_policy}, touch_policy={touch_policy}"
        )
        response = self.protocol.send_apdu(
            0, INS_GENERATE_ASYMMETRIC, 0, slot, Tlv(0xAC, data)
        )
        logger.info(f"Private key generated in slot {slot} of type {key_type}")
        return _parse_device_public_key(key_type, Tlv.unpack(0x7F49, response))

    def attest_key(self, slot: SLOT) -> x509.Certificate:
        """Attest key in slot.

        :param slot: The slot where the key has been generated.
        :return: A X.509 certificate.
        """
        require_version(self.version, (4, 3, 0))
        slot = SLOT(slot)
        response = self.protocol.send_apdu(0, INS_ATTEST, slot, 0)
        logger.debug(f"Attested key in slot {slot}")
        return x509.load_der_x509_certificate(response, default_backend())

    def move_key(self, from_slot: SLOT, to_slot: SLOT) -> None:
        """Move key from one slot to another.

        Requires authentication with management key.

        :param from_slot: The slot containing the key to move.
        :param to_slot: The new slot to move the key to.
        """
        require_version(self.version, (5, 7, 0))
        from_slot = SLOT(from_slot)
        to_slot = SLOT(to_slot)
        logger.debug(f"Moving key from slot {from_slot} to {to_slot}")
        self.protocol.send_apdu(0, INS_MOVE_KEY, to_slot, from_slot)
        logger.info(f"Key moved from slot {from_slot} to {to_slot}")

    def delete_key(self, slot: SLOT) -> None:
        """Delete a key in a slot.

        Requires authentication with management key.

        :param slot: The slot containing the key to delete.
        """
        require_version(self.version, (5, 7, 0))
        slot = SLOT(slot)
        logger.debug(f"Deleting key in slot {slot}")
        self.protocol.send_apdu(0, INS_MOVE_KEY, 0xFF, slot)
        logger.info(f"Key deleted in slot {slot}")

    def _change_reference(self, ins, p2, value1, value2):
        try:
            self.protocol.send_apdu(
                0, ins, 0, p2, _pin_bytes(value1) + _pin_bytes(value2)
            )
        except ApduError as e:
            retries = _retries_from_sw(e.sw)
            if retries is None:
                raise
            if p2 == PIN_P2:
                self._current_pin_retries = retries
            raise InvalidPinError(retries)

    def _get_pin_puk_metadata(self, p2):
        require_version(self.version, (5, 3, 0))
        data = Tlv.parse_dict(self.protocol.send_apdu(0, INS_GET_METADATA, 0, p2))
        attempts = data[TAG_METADATA_RETRIES]
        return PinMetadata(
            data[TAG_METADATA_IS_DEFAULT] != b"\0",
            attempts[INDEX_RETRIES_TOTAL],
            attempts[INDEX_RETRIES_REMAINING],
        )

    def _use_private_key(self, slot, key_type, message, exponentiation):
        try:
            response = self.protocol.send_apdu(
                0,
                INS_AUTHENTICATE,
                key_type,
                slot,
                Tlv(
                    TAG_DYN_AUTH,
                    Tlv(TAG_AUTH_RESPONSE)
                    + Tlv(
                        TAG_AUTH_EXPONENTIATION
                        if exponentiation
                        else TAG_AUTH_CHALLENGE,
                        message,
                    ),
                ),
            )
            return Tlv.unpack(
                TAG_AUTH_RESPONSE,
                Tlv.unpack(
                    TAG_DYN_AUTH,
                    response,
                ),
            )
        except ApduError as e:
            if e.sw == SW.INCORRECT_PARAMETERS:
                raise e  # TODO: Different error, No key?
            raise
