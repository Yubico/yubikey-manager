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

from __future__ import annotations

import gzip
import logging
import re
import warnings
import zlib
from dataclasses import astuple, dataclass
from datetime import date
from enum import Enum, IntEnum, unique
from typing import TYPE_CHECKING, TypeAlias, overload

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .core import (
    BadResponseError,
    InvalidPinError,  # noqa: F401 - re-exported
    NotSupportedError,
    Tlv,
    Version,
    _override_version,
    bytes2int,
    int2bytes,
    require_version,
)
from .core.smartcard import (
    ScpKeyParams,
    SmartCardConnection,
)

if TYPE_CHECKING:
    # This type isn't available on cryptography <40.
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from _yubikit_native.sessions import PivSession as _NativePivSession

logger = logging.getLogger(__name__)


PublicKey: TypeAlias = (
    rsa.RSAPublicKey
    | ec.EllipticCurvePublicKey
    | ed25519.Ed25519PublicKey
    | x25519.X25519PublicKey
)
PrivateKey: TypeAlias = (
    rsa.RSAPrivateKeyWithSerialization
    | ec.EllipticCurvePrivateKeyWithSerialization
    | ed25519.Ed25519PrivateKey
    | x25519.X25519PrivateKey
)


@unique
class ALGORITHM(str, Enum):
    EC = "ec"
    RSA = "rsa"


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
    def algorithm(self) -> ALGORITHM:
        return ALGORITHM.RSA if self.name.startswith("RSA") else ALGORITHM.EC

    @property
    def bit_len(self) -> int:
        if self in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
            return 256
        match = re.search(r"\d+$", self.name)
        if match:
            return int(match.group())
        raise ValueError("No bit_len")

    @classmethod
    def from_public_key(cls, key: PublicKeyTypes) -> KEY_TYPE:
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
    def key_len(self) -> int:
        if self.name == "TDES":
            return 24
        # AES
        return int(self.name[3:]) // 8

    @property
    def challenge_len(self) -> int:
        if self.name == "TDES":
            return 8
        return 16


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
    def from_slot(cls, slot: SLOT) -> OBJECT_ID:
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
INS_GET_SERIAL = 0xF8
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


def _bcd(val, ln=1):
    bits = f"{val % 10:04b}"[::-1]
    bits += str((bits.count("1") + 1) % 2)
    return bits if ln == 1 else _bcd(val // 10, ln - 1) + bits


def _dump_tlv_dict(values: dict[int, bytes | None]) -> bytes:
    return b"".join(
        Tlv(tag, value) for tag, value in values.items() if value is not None
    )


BCD_SS = "11010"
BCD_FS = "10110"
BCD_ES = "11111"

_FASCN_LENS = (4, 4, 6, 1, 1, 10, 1, 4, 1)


@dataclass
class FascN:
    """FASC-N data structure

    https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf
    """

    agency_code: int  # 4 digits
    system_code: int  # 4 digits
    credential_number: int  # 6 digits
    credential_series: int  # 1 digit
    individual_credential_issue: int  # 1 digit
    person_identifier: int  # 10 digits
    organizational_category: int  # 1 digit
    organizational_identifier: int  # 4 digits
    organization_association_category: int  # 1 digit

    def __bytes__(self):
        # Convert values to BCD
        vs = iter(_bcd(v, ln) for v, ln in zip(astuple(self), _FASCN_LENS))

        # Add separators
        bs = (
            BCD_SS
            + next(vs)
            + BCD_FS
            + next(vs)
            + BCD_FS
            + next(vs)
            + BCD_FS
            + next(vs)
            + BCD_FS
            + next(vs)
            + BCD_FS
            + next(vs)
            + next(vs)
            + next(vs)
            + next(vs)
            + BCD_ES
        )

        # Calculate LRC
        lrc = 0
        for i in range(0, len(bs), 5):
            lrc ^= int(bs[i : i + 5], 2)

        return int2bytes(int(bs, 2) << 5 | lrc)

    @classmethod
    def from_bytes(cls, value: bytes) -> FascN:
        bs = f"{bytes2int(value):0200b}"
        ds = [int(bs[i : i + 4][::-1], 2) for i in range(0, 200, 5)]
        args = (
            int("".join(str(d) for d in ds[offs : offs + ln]))
            # offsets considering separators
            for offs, ln in zip((1, 6, 11, 18, 20, 22, 32, 33, 37), _FASCN_LENS)
        )
        return cls(*args)

    def __str__(self):
        return "[%04d-%04d-%06d-%d-%d-%010d%d%04d%d]" % astuple(self)


@dataclass(kw_only=True)
class Chuid:
    buffer_length: int | None = None
    fasc_n: FascN
    agency_code: bytes | None = None
    organizational_identifier: bytes | None = None
    duns: bytes | None = None
    guid: bytes
    expiration_date: date
    authentication_key_map: bytes | None = None
    asymmetric_signature: bytes
    lrc: int | None = None

    def _get_bytes(self, include_signature: bool = True) -> bytes:
        return _dump_tlv_dict(
            {
                0xEE: int2bytes(self.buffer_length)
                if self.buffer_length is not None
                else None,
                0x30: bytes(self.fasc_n),
                0x31: self.agency_code,
                0x32: self.organizational_identifier,
                0x33: self.duns,
                0x34: self.guid,
                0x35: self.expiration_date.isoformat().replace("-", "").encode(),
                0x3D: self.authentication_key_map,
                0x3E: self.asymmetric_signature if include_signature else None,
                TAG_LRC: bytes([self.lrc]) if self.lrc is not None else b"",
            }
        )

    @property
    def tbs_bytes(self) -> bytes:
        return self._get_bytes(include_signature=False)

    def __bytes__(self):
        return self._get_bytes()

    @classmethod
    def from_bytes(cls, value: bytes) -> Chuid:
        data = Tlv.parse_dict(value)
        buffer_length = data.get(0xEE)
        lrc = data.get(TAG_LRC)
        # From Python 3.11: date.fromisoformat(data[0x35])
        d = data[0x35]
        expiration_date = date(int(d[:4]), int(d[4:6]), int(d[6:8]))
        return cls(
            buffer_length=bytes2int(buffer_length) if buffer_length else None,
            fasc_n=FascN.from_bytes(data[0x30]),
            agency_code=data.get(0x31),
            organizational_identifier=data.get(0x32),
            duns=data.get(0x33),
            guid=data[0x34],
            expiration_date=expiration_date,
            authentication_key_map=data.get(0x3D),
            asymmetric_signature=data[0x3E],
            lrc=lrc[0] if lrc else None,
        )


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
    else:
        raise ValueError(f"Unsupported algorithm {key_type.algorithm}")


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

    :deprecated: Use PivSession.check_key_support() instead.
    """
    warnings.warn(
        "Deprecated: use PivSession.check_key_support() instead.",
        DeprecationWarning,
    )
    _do_check_key_support(version, key_type, pin_policy, touch_policy, generate)


def _do_check_key_support(
    version: Version,
    key_type: KEY_TYPE,
    pin_policy: PIN_POLICY,
    touch_policy: TOUCH_POLICY,
    generate: bool = True,
    fips_restrictions: bool = False,
) -> None:
    if key_type == KEY_TYPE.ECCP384:
        require_version(version, (4, 0, 0), "ECCP384 requires YubiKey 4 or later")
    if touch_policy != TOUCH_POLICY.DEFAULT or pin_policy != PIN_POLICY.DEFAULT:
        require_version(
            version, (4, 0, 0), "PIN/Touch policy requires YubiKey 4 or later"
        )
    if touch_policy == TOUCH_POLICY.CACHED:
        require_version(
            version, (4, 3, 0), "Cached touch policy requires YubiKey 4.3 or later"
        )

    # ROCA
    if (4, 2, 0) <= version < (4, 3, 5):
        if generate and key_type.algorithm == ALGORITHM.RSA:
            raise NotSupportedError("RSA key generation not supported on this YubiKey")

    # FIPS
    if fips_restrictions or (4, 4, 0) <= version < (4, 5, 0):
        if key_type in (KEY_TYPE.RSA1024, KEY_TYPE.X25519):
            raise NotSupportedError("RSA 1024 not supported on YubiKey FIPS")
        if pin_policy == PIN_POLICY.NEVER:
            raise NotSupportedError("PIN_POLICY.NEVER not allowed on YubiKey FIPS")

    # New key types
    if key_type in (
        KEY_TYPE.RSA3072,
        KEY_TYPE.RSA4096,
        KEY_TYPE.ED25519,
        KEY_TYPE.X25519,
    ):
        require_version(version, (5, 7, 0), f"{key_type} requires YubiKey 5.7 or later")


def _parse_device_public_key(key_type, encoded):
    data = Tlv.parse_dict(encoded)
    if key_type.algorithm == ALGORITHM.RSA:
        modulus = bytes2int(data[0x81])
        exponent = bytes2int(data[0x82])
        return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
    if key_type == KEY_TYPE.ED25519:
        return ed25519.Ed25519PublicKey.from_public_bytes(data[0x86])
    if key_type == KEY_TYPE.X25519:
        return x25519.X25519PublicKey.from_public_bytes(data[0x86])
    if key_type == KEY_TYPE.ECCP256:
        curve: type[ec.EllipticCurve] = ec.SECP256R1
    elif key_type == KEY_TYPE.ECCP384:
        curve = ec.SECP384R1
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    return ec.EllipticCurvePublicKey.from_encoded_point(curve(), data[0x86])


def decompress_certificate(cert_data: bytes) -> bytes:
    """
    Decompress a compressed certificate using various methods.
    """
    logger.debug("Certificate is compressed, decompressing...")

    match tuple(cert_data[:2]):
        case (0x1F, 0x8B):  # Gzip (most commonly used)
            logger.debug("Decompressing certificate using gzip")
            try:
                return gzip.decompress(cert_data)
            except (zlib.error, gzip.BadGzipFile):
                logger.warning("Failed to decompressed with gzip")
        case (0x01, 0x00):  # Net iD zlib format
            logger.debug("Decompressing certificate using zlib")
            expected_length = int.from_bytes(cert_data[2:4], "little")
            try:
                decompressed = zlib.decompress(cert_data[4:])
                if len(decompressed) != expected_length:
                    logger.error(
                        "Unexpected decompressed length, expected %d, got %d",
                        expected_length,
                        len(decompressed),
                    )
                    raise BadResponseError(
                        "Decompressed length does not match expected length"
                    )

                return decompressed
            except (zlib.error, ValueError):
                logger.warning("Failed to decompress with zlib")
        case _:
            logger.warning("Unknown compression type")

    raise BadResponseError("Failed to decompress certificate")


class PivSession:
    """A session with the PIV application."""

    def __init__(
        self,
        connection: SmartCardConnection,
        scp_key_params: ScpKeyParams | None = None,
    ):
        native = _NativePivSession(connection, scp_key_params)
        self._native = native
        self.connection = connection
        self._version = _override_version.patch(Version(*native.version))
        if self._version != Version(*native.version):
            native.version = tuple(self._version)
        # Re-query management key type now that version may be patched
        try:
            key_type, _, _ = native.get_management_key_metadata()
            self._management_key_type = MANAGEMENT_KEY_TYPE(key_type)
        except Exception:
            self._management_key_type = MANAGEMENT_KEY_TYPE(native.management_key_type)
        self._current_pin_retries = 3
        self._max_pin_retries = 3

        logger.debug(f"PIV session initialized (version={self.version})")

    @property
    def version(self) -> Version:
        """The version of the PIV application,
        typically the same as the YubiKey firmware."""
        return self._version

    @property
    def management_key_type(self) -> MANAGEMENT_KEY_TYPE:
        """The algorithm of the management key currently in use."""
        return self._management_key_type

    def reset(self) -> None:
        """Factory reset the PIV application data.

        This deletes all user-data from the PIV application, and resets the default
        values for PIN, PUK, and management key.
        """
        logger.debug("Performing PIV reset (native)")
        self._native.reset()
        self._current_pin_retries = 3
        self._max_pin_retries = 3
        try:
            key_type, _, _ = self._native.get_management_key_metadata()
            self._management_key_type = MANAGEMENT_KEY_TYPE(key_type)
        except Exception:
            self._management_key_type = MANAGEMENT_KEY_TYPE(
                self._native.management_key_type
            )
        logger.info("PIV application data reset performed")

    def get_serial(self) -> int:
        """Get the serial number of the YubiKey."""
        logger.debug("Getting serial number")
        return self._native.get_serial()

    @overload
    def authenticate(self, management_key: bytes) -> None: ...

    @overload
    # TODO: remove in 6.0
    def authenticate(
        self, key_type: MANAGEMENT_KEY_TYPE, management_key: bytes
    ) -> None: ...

    def authenticate(self, *args, **kwargs) -> None:
        """Authenticate to PIV with management key.

        :param bytes management_key: The management key in raw bytes.
        """
        key_type = kwargs.get("key_type")
        management_key = kwargs.get("management_key")
        if len(args) == 2:
            key_type, management_key = args
        elif len(args) == 1:
            management_key = args[0]
        else:
            key_type = kwargs.get("key_type")
            management_key = kwargs.get("management_key")
        if key_type:
            warnings.warn(
                "Deprecated: call authenticate() without passing management_key_type.",
                DeprecationWarning,
            )
            if self.management_key_type != key_type:
                raise ValueError("Incorrect management key type")
        if not isinstance(management_key, bytes):
            raise TypeError("management_key must be bytes")

        logger.debug("Authenticating with management key (native)")
        self._native.authenticate(management_key)

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

        self._native.set_management_key(int(key_type), management_key, require_touch)
        self._management_key_type = key_type
        logger.info("Management key set")

    def verify_pin(self, pin: str) -> None:
        """Verify the user by PIN.

        NOTE: InvalidPinError raised from this method will cap remaining_attempts
        at 15, even if the true number of remaining attempts is higher.

        :param pin: The PIN.
        """
        logger.debug("Verifying PIN")
        self._native.verify_pin(pin)
        self._current_pin_retries = self._max_pin_retries

    def verify_uv(
        self, temporary_pin: bool = False, check_only: bool = False
    ) -> bytes | None:
        """Verify the user by fingerprint (YubiKey Bio only).

        Fingerprint verification will allow usage of private keys which have a PIN
        policy allowing MATCH. For those using MATCH_ALWAYS, the fingerprint must be
        verified just prior to using the key, or by first requesting a temporary PIN
        and then later verifying the PIN just prior to key use.

        :param temporary_pin: Request a temporary PIN for later use within the session.
        :param check_only: Do not verify the user, instead immediately throw an
            InvalidPinException containing the number of remaining attempts.
        """
        logger.debug("Verifying UV")
        if temporary_pin and check_only:
            raise ValueError(
                "Cannot request temporary PIN when doing check-only verification"
            )

        result = self._native.verify_uv(temporary_pin, check_only)
        if result is not None:
            return bytes(result)
        return None

    def verify_temporary_pin(self, pin: bytes) -> None:
        """Verify the user via temporary PIN.

        :param pin: A temporary PIN previously requested via verify_uv.
        """
        logger.debug("Verifying temporary PIN")
        self._native.verify_temporary_pin(pin)

    def get_pin_attempts(self) -> int:
        """Get remaining PIN attempts."""
        logger.debug("Getting PIN attempts")
        return self._native.get_pin_attempts()

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        """Change the PIN.

        NOTE: InvalidPinError raised from this method will cap remaining_attempts
        at 15, even if the true number of remaining attempts is higher.

        :param old_pin: The current PIN.
        :param new_pin: The new PIN.
        """
        logger.debug("Changing PIN")
        self._native.change_pin(old_pin, new_pin)
        logger.info("New PIN set")

    def change_puk(self, old_puk: str, new_puk: str) -> None:
        """Change the PUK.

        NOTE: InvalidPinError raised from this method will cap remaining_attempts
        at 15, even if the true number of remaining attempts is higher.

        :param old_puk: The current PUK.
        :param new_puk: The new PUK.
        """
        logger.debug("Changing PUK")
        self._native.change_puk(old_puk, new_puk)
        logger.info("New PUK set")

    def unblock_pin(self, puk: str, new_pin: str) -> None:
        """Reset PIN with PUK.

        NOTE: InvalidPinError raised from this method will cap remaining_attempts
        at 15, even if the true number of remaining attempts is higher.

        :param puk: The PUK.
        :param new_pin: The new PIN.
        """
        logger.debug("Using PUK to set new PIN")
        self._native.unblock_pin(puk, new_pin)
        logger.info("New PIN set")

    def set_pin_attempts(self, pin_attempts: int, puk_attempts: int) -> None:
        """Set PIN retries for PIN and PUK.

        Both PIN and PUK will be reset to default values when this is executed.

        Requires authentication with management key and PIN verification.

        :param pin_attempts: The PIN attempts.
        :param puk_attempts: The PUK attempts.
        """
        logger.debug(f"Setting PIN/PUK attempts ({pin_attempts}, {puk_attempts})")
        self._native.set_pin_attempts(pin_attempts, puk_attempts)
        self._max_pin_retries = pin_attempts
        self._current_pin_retries = pin_attempts
        logger.info("PIN/PUK attempts set")

    def get_pin_metadata(self) -> PinMetadata:
        """Get PIN metadata."""
        logger.debug("Getting PIN metadata")
        default_value, total_attempts, attempts_remaining = (
            self._native.get_pin_metadata()
        )
        return PinMetadata(default_value, total_attempts, attempts_remaining)

    def get_puk_metadata(self) -> PinMetadata:
        """Get PUK metadata."""
        logger.debug("Getting PUK metadata")
        default_value, total_attempts, attempts_remaining = (
            self._native.get_puk_metadata()
        )
        return PinMetadata(default_value, total_attempts, attempts_remaining)

    def get_management_key_metadata(self) -> ManagementKeyMetadata:
        """Get management key metadata."""
        logger.debug("Getting management key metadata")
        key_type, default_value, touch_policy = (
            self._native.get_management_key_metadata()
        )
        return ManagementKeyMetadata(
            MANAGEMENT_KEY_TYPE(key_type),
            default_value,
            TOUCH_POLICY(touch_policy),
        )

    def get_slot_metadata(self, slot: SLOT) -> SlotMetadata:
        """Get slot metadata.

        :param slot: The slot to get metadata from.
        """
        slot = SLOT(slot)
        logger.debug(f"Getting metadata for slot {slot}")
        key_type, pin_policy, touch_policy, generated, public_key_encoded = (
            self._native.get_slot_metadata(int(slot))
        )
        return SlotMetadata(
            KEY_TYPE(key_type),
            PIN_POLICY(pin_policy),
            TOUCH_POLICY(touch_policy),
            generated,
            bytes(public_key_encoded),
        )

    def get_bio_metadata(self) -> BioMetadata:
        """Get YubiKey Bio metadata.

        This tells you if fingerprints are enrolled or not, how many fingerprint
        verification attempts remain, and whether or not a temporary PIN is currently
        active.
        """
        logger.debug("Getting bio metadata")
        configured, attempts_remaining, temporary_pin = self._native.get_bio_metadata()
        return BioMetadata(configured, attempts_remaining, temporary_pin)

    def sign(
        self,
        slot: SLOT,
        key_type: KEY_TYPE,
        message: bytes,
        hash_algorithm: hashes.HashAlgorithm | None,
        padding: AsymmetricPadding | None = None,
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
        return bytes(self._native.sign(int(slot), int(key_type), padded))

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
            f"Decrypting data with key in slot {slot} of type {key_type} using "
            f"padding={padding}"
        )
        padded = bytes(self._native.decrypt(int(slot), cipher_text))
        return _unpad_message(padded, padding)

    def calculate_secret(
        self,
        slot: SLOT,
        peer_public_key: (
            ec.EllipticCurvePublicKeyWithSerialization | x25519.X25519PublicKey
        ),
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
        return bytes(self._native.calculate_secret(int(slot), int(key_type), data))

    def get_object(self, object_id: int) -> bytes:
        """Get object by ID.

        Requires PIN verification for protected objects.

        :param object_id: The object identifier.
        """
        logger.debug(f"Reading data from object slot {hex(object_id)}")
        return bytes(self._native.get_object(object_id))

    def put_object(self, object_id: int, data: bytes | None = None) -> None:
        """Write data to PIV object.

        Requires authentication with management key.

        :param object_id: The object identifier.
        :param data: The object data.
        """
        self._native.put_object(object_id, data)
        logger.info(f"Data written to object slot {hex(object_id)}")

    def get_certificate(self, slot: SLOT) -> x509.Certificate:
        """Get certificate from slot.

        :param slot: The slot to get the certificate from.
        """
        slot = SLOT(slot)
        logger.debug(f"Reading certificate in slot {slot}")
        der_bytes = bytes(self._native.get_certificate(int(slot)))
        try:
            return x509.load_der_x509_certificate(der_bytes, default_backend())
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
        cert_der = certificate.public_bytes(Encoding.DER)
        self._native.put_certificate(int(slot), cert_der, compress)
        logger.info(f"Certificate written to slot {slot}, compression={compress}")

    def delete_certificate(self, slot: SLOT) -> None:
        """Delete certificate.

        Requires authentication with management key.

        :param slot: The slot to delete the certificate from.
        """
        slot = SLOT(slot)
        logger.debug(f"Deleting certificate in slot {slot}")
        self._native.delete_certificate(int(slot))

    def put_key(
        self,
        slot: SLOT,
        private_key: PrivateKey,
        pin_policy: PIN_POLICY = PIN_POLICY.DEFAULT,
        touch_policy: TOUCH_POLICY = TOUCH_POLICY.DEFAULT,
    ) -> KEY_TYPE:
        """Import a private key to slot.

        Requires authentication with management key.

        :param slot: The slot to import the key to.
        :param private_key: The private key to import.
        :param pin_policy: The PIN policy.
        :param touch_policy: The touch policy.
        """
        slot = SLOT(slot)
        key_type = KEY_TYPE.from_public_key(private_key.public_key())
        self.check_key_support(key_type, pin_policy, touch_policy, False)

        if key_type.algorithm == ALGORITHM.RSA:
            key_der = private_key.private_bytes(
                Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption()
            )
        elif key_type in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
            key_der = private_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
        else:
            assert isinstance(  # noqa: S101
                private_key, ec.EllipticCurvePrivateKey
            )
            key_der = int2bytes(
                private_key.private_numbers().private_value,
                key_type.bit_len // 8,
            )
        self._native.put_key(
            int(slot),
            int(key_type),
            key_der,
            int(pin_policy),
            int(touch_policy),
        )
        logger.info(f"Private key imported in slot {slot} of type {key_type}")
        return key_type

    def generate_key(
        self,
        slot: SLOT,
        key_type: KEY_TYPE,
        pin_policy: PIN_POLICY = PIN_POLICY.DEFAULT,
        touch_policy: TOUCH_POLICY = TOUCH_POLICY.DEFAULT,
    ) -> PublicKey:
        """Generate private key in slot.

        Requires authentication with management key.

        :param slot: The slot to generate the private key in.
        :param key_type: The key type.
        :param pin_policy: The PIN policy.
        :param touch_policy: The touch policy.
        """
        slot = SLOT(slot)
        key_type = KEY_TYPE(key_type)
        self.check_key_support(key_type, pin_policy, touch_policy, True)

        logger.debug(
            f"Generating key with pin_policy={pin_policy}, touch_policy={touch_policy}"
        )
        pub_key_encoded = bytes(
            self._native.generate_key(
                int(slot),
                int(key_type),
                int(pin_policy),
                int(touch_policy),
            )
        )
        logger.info(f"Private key generated in slot {slot} of type {key_type}")
        return _parse_device_public_key(key_type, pub_key_encoded)

    def attest_key(self, slot: SLOT) -> x509.Certificate:
        """Attest key in slot.

        :param slot: The slot where the key has been generated.
        :return: A X.509 certificate.
        """
        require_version(self.version, (4, 3, 0))
        slot = SLOT(slot)
        der_bytes = bytes(self._native.attest_key(int(slot)))
        logger.debug(f"Attested key in slot {slot}")
        return x509.load_der_x509_certificate(der_bytes, default_backend())

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
        self._native.move_key(int(from_slot), int(to_slot))
        logger.info(f"Key moved from slot {from_slot} to {to_slot}")

    def delete_key(self, slot: SLOT) -> None:
        """Delete a key in a slot.

        Requires authentication with management key.

        :param slot: The slot containing the key to delete.
        """
        require_version(self.version, (5, 7, 0))
        slot = SLOT(slot)
        logger.debug(f"Deleting key in slot {slot}")
        self._native.delete_key(int(slot))
        logger.info(f"Key deleted in slot {slot}")

    def check_key_support(
        self,
        key_type: KEY_TYPE,
        pin_policy: PIN_POLICY,
        touch_policy: TOUCH_POLICY,
        generate: bool,
        fips_restrictions: bool = False,
    ) -> None:
        """Check if a key type is supported by this YubiKey.

        This method will return None if the key (with PIN and touch policies) is
        supported, or it will raise a NotSupportedError if it is not.

        Set the generate parameter to True to check if generating the key is supported
        (in addition to importing).

        Set fips_restrictions to True to apply restrictions based on FIPS status.
        """

        self._native.check_key_support(
            int(key_type),
            int(pin_policy),
            int(touch_policy),
            generate,
            fips_restrictions,
        )
        if pin_policy in (PIN_POLICY.MATCH_ONCE, PIN_POLICY.MATCH_ALWAYS):
            self.get_bio_metadata()
