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
    AID,
    CommandError,
    NotSupportedError,
    BadResponseError,
)
from .core.smartcard import (
    SmartCardConnection,
    SmartCardProtocol,
    ApduError,
    SW,
    ApduFormat,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.backends import default_backend

from dataclasses import dataclass
from enum import Enum, IntEnum, unique, auto
from typing import Optional, Union, cast

import logging
import os
import re


logger = logging.getLogger(__name__)


class ALGORITHM(Enum):
    EC = auto()
    RSA = auto()


# Don't treat pre 1.0 versions as "developer builds".
def require_version(my_version: Version, *args, **kwargs):
    if my_version <= (0, 1, 3):  # Last pre 1.0 release of ykneo-piv
        my_version = Version(1, 0, 0)
    _require_version(my_version, *args, **kwargs)


@unique
class KEY_TYPE(IntEnum):
    RSA1024 = 0x06
    RSA2048 = 0x07
    ECCP256 = 0x11
    ECCP384 = 0x14

    @property
    def algorithm(self):
        return ALGORITHM.EC if self.name.startswith("ECC") else ALGORITHM.RSA

    @property
    def bit_len(self):
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
                pass  # Fall through to ValueError
        elif isinstance(key, ec.EllipticCurvePublicKey):
            curve_name = key.curve.name
            if curve_name == "secp256r1":
                return cls.ECCP256
            elif curve_name == "secp384r1":
                return cls.ECCP384
            raise ValueError(f"Unsupported EC curve: {curve_name}")
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


# The card management slot is special, we don't include it in SLOT below
SLOT_CARD_MANAGEMENT = 0x9B


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

# Instruction set
INS_VERIFY = 0x20
INS_CHANGE_REFERENCE = 0x24
INS_RESET_RETRY = 0x2C
INS_GENERATE_ASYMMETRIC = 0x47
INS_AUTHENTICATE = 0x87
INS_GET_DATA = 0xCB
INS_PUT_DATA = 0xDB
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

ORIGIN_GENERATED = 1
ORIGIN_IMPORTED = 2

INDEX_PIN_POLICY = 0
INDEX_TOUCH_POLICY = 1
INDEX_RETRIES_TOTAL = 0
INDEX_RETRIES_REMAINING = 1

PIN_P2 = 0x80
PUK_P2 = 0x81


class InvalidPinError(CommandError):
    def __init__(self, attempts_remaining):
        super(InvalidPinError, self).__init__(
            "Invalid PIN/PUK. Remaining attempts: %d" % attempts_remaining
        )
        self.attempts_remaining = attempts_remaining


def _pin_bytes(pin):
    pin = pin.encode()
    if len(pin) > PIN_LEN:
        raise ValueError("PIN/PUK must be no longer than 8 bytes")
    return pin.ljust(PIN_LEN, b"\xff")


def _retries_from_sw(version, sw):
    if sw == SW.AUTH_METHOD_BLOCKED:
        return 0
    if version < (1, 0, 4):
        if 0x6300 <= sw <= 0x63FF:
            return sw & 0xFF
    else:
        if 0x63C0 <= sw <= 0x63CF:
            return sw & 0x0F
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


def _pad_message(key_type, message, hash_algorithm, padding):
    if key_type.algorithm == ALGORITHM.EC:
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


def _parse_device_public_key(key_type, encoded):
    data = Tlv.parse_dict(encoded)
    if key_type.algorithm == ALGORITHM.RSA:
        modulus = bytes2int(data[0x81])
        exponent = bytes2int(data[0x82])
        return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
    else:
        if key_type == KEY_TYPE.ECCP256:
            curve = ec.SECP256R1
        else:
            curve = ec.SECP384R1

        try:
            # Added in cryptography 2.5
            return ec.EllipticCurvePublicKey.from_encoded_point(curve(), data[0x86])
        except AttributeError:
            return ec.EllipticCurvePublicNumbers.from_encoded_point(
                curve(), data[0x86]
            ).public_key(default_backend())


class PivSession:
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

    @property
    def version(self) -> Version:
        return self._version

    def reset(self) -> None:
        # Block PIN
        counter = self.get_pin_attempts()
        while counter > 0:
            try:
                self.verify_pin("")
            except InvalidPinError as e:
                counter = e.attempts_remaining

        # Block PUK
        counter = 1
        while counter > 0:
            try:
                self._change_reference(INS_RESET_RETRY, PIN_P2, "", "")
            except InvalidPinError as e:
                counter = e.attempts_remaining

        # Reset
        self.protocol.send_apdu(0, INS_RESET, 0, 0)
        self._current_pin_retries = 3
        self._max_pin_retries = 3

    def authenticate(
        self, key_type: MANAGEMENT_KEY_TYPE, management_key: bytes
    ) -> None:
        key_type = MANAGEMENT_KEY_TYPE(key_type)
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
        key_type = MANAGEMENT_KEY_TYPE(key_type)
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

    def verify_pin(self, pin: str) -> None:
        try:
            self.protocol.send_apdu(0, INS_VERIFY, 0, PIN_P2, _pin_bytes(pin))
            self._current_pin_retries = self._max_pin_retries
        except ApduError as e:
            retries = _retries_from_sw(self.version, e.sw)
            if retries is None:
                raise
            self._current_pin_retries = retries
            raise InvalidPinError(retries)

    def get_pin_attempts(self) -> int:
        try:
            return self.get_pin_metadata().attempts_remaining
        except NotSupportedError:
            try:
                self.protocol.send_apdu(0, INS_VERIFY, 0, PIN_P2)
                # Already verified, no way to know true count
                return self._current_pin_retries
            except ApduError as e:
                retries = _retries_from_sw(self.version, e.sw)
                if retries is None:
                    raise
                self._current_pin_retries = retries
                return retries

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        self._change_reference(INS_CHANGE_REFERENCE, PIN_P2, old_pin, new_pin)

    def change_puk(self, old_puk: str, new_puk: str) -> None:
        self._change_reference(INS_CHANGE_REFERENCE, PUK_P2, old_puk, new_puk)

    def unblock_pin(self, puk: str, new_pin: str) -> None:
        self._change_reference(INS_RESET_RETRY, PIN_P2, puk, new_pin)

    def set_pin_attempts(self, pin_attempts: int, puk_attempts: int) -> None:
        self.protocol.send_apdu(0, INS_SET_PIN_RETRIES, pin_attempts, puk_attempts)
        self._max_pin_retries = pin_attempts
        self._current_pin_retries = pin_attempts

    def get_pin_metadata(self) -> PinMetadata:
        return self._get_pin_puk_metadata(PIN_P2)

    def get_puk_metadata(self) -> PinMetadata:
        return self._get_pin_puk_metadata(PUK_P2)

    def get_management_key_metadata(self) -> ManagementKeyMetadata:
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

    def sign(
        self,
        slot: SLOT,
        key_type: KEY_TYPE,
        message: bytes,
        hash_algorithm: hashes.HashAlgorithm,
        padding: Optional[AsymmetricPadding] = None,
    ) -> bytes:
        key_type = KEY_TYPE(key_type)
        padded = _pad_message(key_type, message, hash_algorithm, padding)
        return self._use_private_key(slot, key_type, padded, False)

    def decrypt(
        self, slot: SLOT, cipher_text: bytes, padding: AsymmetricPadding
    ) -> bytes:
        if len(cipher_text) == 1024 // 8:
            key_type = KEY_TYPE.RSA1024
        elif len(cipher_text) == 2048 // 8:
            key_type = KEY_TYPE.RSA2048
        else:
            raise ValueError("Invalid length of ciphertext")
        padded = self._use_private_key(slot, key_type, cipher_text, False)
        return _unpad_message(padded, padding)

    def calculate_secret(
        self, slot: SLOT, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        key_type = KEY_TYPE.from_public_key(peer_public_key)
        if key_type.algorithm != ALGORITHM.EC:
            raise ValueError("Unsupported key type")
        data = peer_public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return self._use_private_key(slot, key_type, data, True)

    def get_object(self, object_id: int) -> bytes:
        if object_id == OBJECT_ID.DISCOVERY:
            expected: int = OBJECT_ID.DISCOVERY
        else:
            expected = TAG_OBJ_DATA

        try:
            return Tlv.unpack(
                expected,
                self.protocol.send_apdu(
                    0, INS_GET_DATA, 0x3F, 0xFF, Tlv(TAG_OBJ_ID, int2bytes(object_id)),
                ),
            )
        except ValueError as e:
            raise BadResponseError("Malformed object data", e)

    def put_object(self, object_id: int, data: Optional[bytes] = None) -> None:
        self.protocol.send_apdu(
            0,
            INS_PUT_DATA,
            0x3F,
            0xFF,
            Tlv(TAG_OBJ_ID, int2bytes(object_id)) + Tlv(TAG_OBJ_DATA, data or b""),
        )

    def get_certificate(self, slot: SLOT) -> x509.Certificate:
        try:
            data = Tlv.parse_dict(self.get_object(OBJECT_ID.from_slot(slot)))
        except ValueError:
            raise BadResponseError("Malformed certificate data object")

        cert_info = data.get(TAG_CERT_INFO)
        if cert_info and cert_info[0] != 0:
            raise NotSupportedError("Compressed certificates are not supported")

        try:
            return x509.load_der_x509_certificate(
                data[TAG_CERTIFICATE], default_backend()
            )
        except Exception as e:
            raise BadResponseError("Invalid certificate", e)

    def put_certificate(self, slot: SLOT, certificate: x509.Certificate) -> None:
        cert_data = certificate.public_bytes(Encoding.DER)
        data = (
            Tlv(TAG_CERTIFICATE, cert_data) + Tlv(TAG_CERT_INFO, b"\0") + Tlv(TAG_LRC)
        )
        self.put_object(OBJECT_ID.from_slot(slot), data)

    def delete_certificate(self, slot: SLOT) -> None:
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
        key_type = KEY_TYPE.from_public_key(private_key.public_key())
        check_key_support(self.version, key_type, pin_policy, touch_policy, False)
        ln = key_type.bit_len // 8
        numbers = private_key.private_numbers()
        if key_type.algorithm == ALGORITHM.RSA:
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
        else:
            numbers = cast(ec.EllipticCurvePrivateNumbers, numbers)
            data = Tlv(0x06, int2bytes(numbers.private_value, ln))
        if pin_policy:
            data += Tlv(TAG_PIN_POLICY, int2bytes(pin_policy))
        if touch_policy:
            data += Tlv(TAG_TOUCH_POLICY, int2bytes(touch_policy))
        self.protocol.send_apdu(0, INS_IMPORT_KEY, key_type, slot, data)
        return key_type

    def generate_key(
        self,
        slot: SLOT,
        key_type: KEY_TYPE,
        pin_policy: PIN_POLICY = PIN_POLICY.DEFAULT,
        touch_policy: TOUCH_POLICY = TOUCH_POLICY.DEFAULT,
    ) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        key_type = KEY_TYPE(key_type)
        check_key_support(self.version, key_type, pin_policy, touch_policy, True)
        data: bytes = Tlv(TAG_GEN_ALGORITHM, int2bytes(key_type))
        if pin_policy:
            data += Tlv(TAG_PIN_POLICY, int2bytes(pin_policy))
        if touch_policy:
            data += Tlv(TAG_TOUCH_POLICY, int2bytes(touch_policy))
        response = self.protocol.send_apdu(
            0, INS_GENERATE_ASYMMETRIC, 0, slot, Tlv(0xAC, data)
        )
        return _parse_device_public_key(key_type, Tlv.unpack(0x7F49, response))

    def attest_key(self, slot: SLOT) -> x509.Certificate:
        require_version(self.version, (4, 3, 0))
        response = self.protocol.send_apdu(0, INS_ATTEST, slot, 0)
        return x509.load_der_x509_certificate(response, default_backend())

    def _change_reference(self, ins, p2, value1, value2):
        try:
            self.protocol.send_apdu(
                0, ins, 0, p2, _pin_bytes(value1) + _pin_bytes(value2)
            )
        except ApduError as e:
            retries = _retries_from_sw(self.version, e.sw)
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
            return Tlv.unpack(TAG_AUTH_RESPONSE, Tlv.unpack(TAG_DYN_AUTH, response,),)
        except ApduError as e:
            if e.sw == SW.INCORRECT_PARAMETERS:
                raise e  # TODO: Different error, No key?
            raise
