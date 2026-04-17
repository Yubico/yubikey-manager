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
import os
import struct
from dataclasses import dataclass
from enum import Enum, IntEnum, IntFlag, unique
from typing import (
    ClassVar,
    Mapping,
    Sequence,
    SupportsBytes,
    TypeAlias,
)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from _yubikit_native.sessions import OpenPgpSession as _NativeOpenPgpSession

from .core import (
    NotSupportedError,
    Oid,
    Session,
    Tlv,
    Version,
    bytes2int,
    int2bytes,
)
from .core.smartcard import (
    ScpKeyParams,
    SmartCardConnection,
)

logger = logging.getLogger(__name__)

DEFAULT_USER_PIN = "123456"
DEFAULT_ADMIN_PIN = "12345678"


@unique
class UIF(IntEnum):  # noqa: N801
    OFF = 0x00
    ON = 0x01
    FIXED = 0x02
    CACHED = 0x03
    CACHED_FIXED = 0x04

    @classmethod
    def parse(cls, encoded: bytes):
        return cls(encoded[0])

    def __bytes__(self) -> bytes:
        return struct.pack(">BB", self, GENERAL_FEATURE_MANAGEMENT.BUTTON)

    @property
    def is_fixed(self) -> bool:
        return self in (UIF.FIXED, UIF.CACHED_FIXED)

    @property
    def is_cached(self) -> bool:
        return self in (UIF.CACHED, UIF.CACHED_FIXED)

    def __str__(self):
        if self == UIF.FIXED:
            return "On (fixed)"
        if self == UIF.CACHED_FIXED:
            return "Cached (fixed)"
        return self.name[0] + self.name[1:].lower()


@unique
class PIN_POLICY(IntEnum):  # noqa: N801
    ALWAYS = 0x00
    ONCE = 0x01

    def __str__(self):
        return self.name[0] + self.name[1:].lower()


@unique
class INS(IntEnum):  # noqa: N801
    VERIFY = 0x20
    CHANGE_PIN = 0x24
    RESET_RETRY_COUNTER = 0x2C
    PSO = 0x2A
    ACTIVATE = 0x44
    GENERATE_ASYM = 0x47
    GET_CHALLENGE = 0x84
    INTERNAL_AUTHENTICATE = 0x88
    SELECT_DATA = 0xA5
    GET_DATA = 0xCA
    PUT_DATA = 0xDA
    PUT_DATA_ODD = 0xDB
    TERMINATE = 0xE6
    GET_VERSION = 0xF1
    SET_PIN_RETRIES = 0xF2
    GET_ATTESTATION = 0xFB


_INVALID_PIN = b"\0" * 8


TAG_DISCRETIONARY = 0x73
TAG_EXTENDED_CAPABILITIES = 0xC0
TAG_FINGERPRINTS = 0xC5
TAG_CA_FINGERPRINTS = 0xC6
TAG_GENERATION_TIMES = 0xCD
TAG_SIGNATURE_COUNTER = 0x93
TAG_KEY_INFORMATION = 0xDE


@unique
class PW(IntEnum):
    USER = 0x81
    RESET = 0x82
    ADMIN = 0x83


@unique
class DO(IntEnum):
    PRIVATE_USE_1 = 0x0101
    PRIVATE_USE_2 = 0x0102
    PRIVATE_USE_3 = 0x0103
    PRIVATE_USE_4 = 0x0104
    AID = 0x4F
    NAME = 0x5B
    LOGIN_DATA = 0x5E
    LANGUAGE = 0xEF2D
    SEX = 0x5F35
    URL = 0x5F50
    HISTORICAL_BYTES = 0x5F52
    EXTENDED_LENGTH_INFO = 0x7F66
    GENERAL_FEATURE_MANAGEMENT = 0x7F74
    CARDHOLDER_RELATED_DATA = 0x65
    APPLICATION_RELATED_DATA = 0x6E
    ALGORITHM_ATTRIBUTES_SIG = 0xC1
    ALGORITHM_ATTRIBUTES_DEC = 0xC2
    ALGORITHM_ATTRIBUTES_AUT = 0xC3
    ALGORITHM_ATTRIBUTES_ATT = 0xDA
    PW_STATUS_BYTES = 0xC4
    FINGERPRINT_SIG = 0xC7
    FINGERPRINT_DEC = 0xC8
    FINGERPRINT_AUT = 0xC9
    FINGERPRINT_ATT = 0xDB
    CA_FINGERPRINT_1 = 0xCA
    CA_FINGERPRINT_2 = 0xCB
    CA_FINGERPRINT_3 = 0xCC
    CA_FINGERPRINT_4 = 0xDC
    GENERATION_TIME_SIG = 0xCE
    GENERATION_TIME_DEC = 0xCF
    GENERATION_TIME_AUT = 0xD0
    GENERATION_TIME_ATT = 0xDD
    RESETTING_CODE = 0xD3
    UIF_SIG = 0xD6
    UIF_DEC = 0xD7
    UIF_AUT = 0xD8
    UIF_ATT = 0xD9
    SECURITY_SUPPORT_TEMPLATE = 0x7A
    CARDHOLDER_CERTIFICATE = 0x7F21
    KDF = 0xF9
    ALGORITHM_INFORMATION = 0xFA
    ATT_CERTIFICATE = 0xFC


def _bcd(value: int) -> int:
    return 10 * (value >> 4) + (value & 0xF)


class OpenPgpAid(bytes):
    """OpenPGP Application Identifier (AID)

    The OpenPGP AID is a string of bytes identifying the OpenPGP application.
    It also embeds some values which are accessible though properties.
    """

    @property
    def version(self) -> tuple[int, int]:
        """OpenPGP version (tuple of 2 integers: main version, secondary version)."""
        return (_bcd(self[6]), _bcd(self[7]))

    @property
    def manufacturer(self) -> int:
        """16-bit integer value identifying the manufacturer of the device.

        This should be 6 for Yubico devices.
        """
        return bytes2int(self[8:10])

    @property
    def serial(self) -> int:
        """The serial number of the YubiKey.

        NOTE: This value is encoded in BCD. In the event of an invalid value (hex A-F)
        the entire 4 byte value will instead be decoded as an unsigned integer,
        and negated.
        """
        try:
            return int(self[10:14].hex())
        except ValueError:
            # Not valid BCD, treat as an unsigned integer, and return a negative value
            return -struct.unpack(">I", self[10:14])[0]


@unique
class EXTENDED_CAPABILITY_FLAGS(IntFlag):
    KDF = 1 << 0
    PSO_DEC_ENC_AES = 1 << 1
    ALGORITHM_ATTRIBUTES_CHANGEABLE = 1 << 2
    PRIVATE_USE = 1 << 3
    PW_STATUS_CHANGEABLE = 1 << 4
    KEY_IMPORT = 1 << 5
    GET_CHALLENGE = 1 << 6
    SECURE_MESSAGING = 1 << 7


@dataclass
class CardholderRelatedData:
    name: bytes
    language: bytes
    sex: int

    @classmethod
    def parse(cls, encoded) -> CardholderRelatedData:
        data = Tlv.parse_dict(Tlv.unpack(DO.CARDHOLDER_RELATED_DATA, encoded))
        return cls(
            data[DO.NAME],
            data[DO.LANGUAGE],
            data[DO.SEX][0],
        )


@dataclass
class ExtendedLengthInfo:
    request_max_bytes: int
    response_max_bytes: int

    @classmethod
    def parse(cls, encoded) -> ExtendedLengthInfo:
        data = Tlv.parse_list(encoded)
        return cls(
            bytes2int(Tlv.unpack(0x02, data[0])),
            bytes2int(Tlv.unpack(0x02, data[1])),
        )


@unique
class GENERAL_FEATURE_MANAGEMENT(IntFlag):
    TOUCHSCREEN = 1 << 0
    MICROPHONE = 1 << 1
    LOUDSPEAKER = 1 << 2
    LED = 1 << 3
    KEYPAD = 1 << 4
    BUTTON = 1 << 5
    BIOMETRIC = 1 << 6
    DISPLAY = 1 << 7


@dataclass
class ExtendedCapabilities:
    flags: EXTENDED_CAPABILITY_FLAGS
    sm_algorithm: int
    challenge_max_length: int
    certificate_max_length: int
    special_do_max_length: int
    pin_block_2_format: bool
    mse_command: bool

    @classmethod
    def parse(cls, encoded: bytes) -> ExtendedCapabilities:
        return cls(
            EXTENDED_CAPABILITY_FLAGS(encoded[0]),
            encoded[1],
            bytes2int(encoded[2:4]),
            bytes2int(encoded[4:6]),
            bytes2int(encoded[6:8]),
            encoded[8] == 1,
            encoded[9] == 1,
        )


@dataclass
class PwStatus:
    pin_policy_user: PIN_POLICY
    max_len_user: int
    max_len_reset: int
    max_len_admin: int
    attempts_user: int
    attempts_reset: int
    attempts_admin: int

    def get_max_len(self, pw: PW) -> int:
        return getattr(self, f"max_len_{pw.name.lower()}")

    def get_attempts(self, pw: PW) -> int:
        return getattr(self, f"attempts_{pw.name.lower()}")

    @classmethod
    def parse(cls, encoded: bytes) -> PwStatus:
        try:
            policy = PIN_POLICY(encoded[0])
        except ValueError:
            policy = PIN_POLICY.ONCE
        return cls(
            policy,
            encoded[1],
            encoded[2],
            encoded[3],
            encoded[4],
            encoded[5],
            encoded[6],
        )


@unique
class CRT(bytes, Enum):
    """Control Reference Template values."""

    SIG = Tlv(0xB6)
    DEC = Tlv(0xB8)
    AUT = Tlv(0xA4)
    ATT = Tlv(0xB6, Tlv(0x84, b"\x81"))


@unique
class KEY_REF(IntEnum):  # noqa: N801
    SIG = 0x01
    DEC = 0x02
    AUT = 0x03
    ATT = 0x81

    @property
    def algorithm_attributes_do(self) -> DO:
        return getattr(DO, f"ALGORITHM_ATTRIBUTES_{self.name}")

    @property
    def uif_do(self) -> DO:
        return getattr(DO, f"UIF_{self.name}")

    @property
    def generation_time_do(self) -> DO:
        return getattr(DO, f"GENERATION_TIME_{self.name}")

    @property
    def fingerprint_do(self) -> DO:
        return getattr(DO, f"FINGERPRINT_{self.name}")

    @property
    def crt(self) -> CRT:
        return getattr(CRT, self.name)


@unique
class KEY_STATUS(IntEnum):
    NONE = 0
    GENERATED = 1
    IMPORTED = 2


KeyInformation = Mapping[KEY_REF, KEY_STATUS]
Fingerprints = Mapping[KEY_REF, bytes]
GenerationTimes = Mapping[KEY_REF, int]
EcPublicKey: TypeAlias = (
    ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | x25519.X25519PublicKey
)
PublicKey: TypeAlias = EcPublicKey | rsa.RSAPublicKey
EcPrivateKey: TypeAlias = (
    ec.EllipticCurvePrivateKeyWithSerialization
    | ed25519.Ed25519PrivateKey
    | x25519.X25519PrivateKey
)
PrivateKey: TypeAlias = rsa.RSAPrivateKeyWithSerialization | EcPrivateKey


@dataclass
class AlgorithmAttributes(abc.ABC):
    """OpenPGP key algorithm attributes."""

    _supported_ids: ClassVar[Sequence[int]]
    algorithm_id: int

    @classmethod
    def parse(cls, encoded: bytes) -> AlgorithmAttributes:
        algorithm_id = encoded[0]
        for sub_cls in cls.__subclasses__():
            if algorithm_id in sub_cls._supported_ids:
                return sub_cls._parse_data(algorithm_id, encoded[1:])
        raise ValueError("Unsupported algorithm ID")

    @abc.abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_data(cls, alg: int, encoded: bytes) -> AlgorithmAttributes:
        raise NotImplementedError()


@unique
class RSA_SIZE(IntEnum):
    RSA2048 = 2048
    RSA3072 = 3072
    RSA4096 = 4096


@unique
class RSA_IMPORT_FORMAT(IntEnum):
    STANDARD = 0
    STANDARD_W_MOD = 1
    CRT = 2
    CRT_W_MOD = 3


@dataclass
class RsaAttributes(AlgorithmAttributes):
    _supported_ids = [0x01]

    n_len: int
    e_len: int
    import_format: RSA_IMPORT_FORMAT

    @classmethod
    def create(
        cls,
        n_len: RSA_SIZE,
        import_format: RSA_IMPORT_FORMAT = RSA_IMPORT_FORMAT.STANDARD,
    ) -> RsaAttributes:
        return cls(0x01, n_len, 17, import_format)

    @classmethod
    def _parse_data(cls, alg, encoded) -> RsaAttributes:
        n, e, f = struct.unpack(">HHB", encoded)
        return cls(alg, n, e, RSA_IMPORT_FORMAT(f))

    def __bytes__(self) -> bytes:
        return struct.pack(
            ">BHHB", self.algorithm_id, self.n_len, self.e_len, self.import_format
        )


class CurveOid(Oid):
    def _get_name(self) -> str:
        for oid in OID:
            if self.startswith(oid):
                return oid.name
        return "Unknown Curve"

    def __str__(self) -> str:
        return self._get_name()

    def __repr__(self) -> str:
        return f"{self._get_name()}({self.dotted_string})"


class OID(CurveOid, Enum):
    SECP256R1 = CurveOid.from_string("1.2.840.10045.3.1.7")
    SECP256K1 = CurveOid.from_string("1.3.132.0.10")
    SECP384R1 = CurveOid.from_string("1.3.132.0.34")
    SECP521R1 = CurveOid.from_string("1.3.132.0.35")
    BrainpoolP256R1 = CurveOid.from_string("1.3.36.3.3.2.8.1.1.7")
    BrainpoolP384R1 = CurveOid.from_string("1.3.36.3.3.2.8.1.1.11")
    BrainpoolP512R1 = CurveOid.from_string("1.3.36.3.3.2.8.1.1.13")
    X25519 = CurveOid.from_string("1.3.6.1.4.1.3029.1.5.1")
    Ed25519 = CurveOid.from_string("1.3.6.1.4.1.11591.15.1")

    @classmethod
    def _from_key(cls, private_key: EcPrivateKey) -> CurveOid:
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            name = private_key.curve.name.lower()
        else:
            if isinstance(private_key, ed25519.Ed25519PrivateKey):
                name = "ed25519"
            elif isinstance(private_key, x25519.X25519PrivateKey):
                name = "x25519"
        for oid in cls:
            if oid.name.lower() == name:
                return oid
        raise ValueError("Unsupported private key")

    def __repr__(self) -> str:
        return repr(self.value)

    def __str__(self) -> str:
        return str(self.value)


@unique
class EC_IMPORT_FORMAT(IntEnum):
    STANDARD = 0
    STANDARD_W_PUBKEY = 0xFF


@dataclass
class EcAttributes(AlgorithmAttributes):
    _supported_ids = [0x12, 0x13, 0x16]

    oid: CurveOid
    import_format: EC_IMPORT_FORMAT

    @classmethod
    def create(cls, key_ref: KEY_REF, oid: CurveOid) -> EcAttributes:
        if oid == OID.Ed25519:
            alg = 0x16  # EdDSA
        elif key_ref == KEY_REF.DEC:
            alg = 0x12  # ECDH
        else:
            alg = 0x13  # ECDSA
        return cls(alg, oid, EC_IMPORT_FORMAT.STANDARD)

    @classmethod
    def _parse_data(cls, alg, encoded) -> EcAttributes:
        if encoded[-1] == 0xFF:
            f = EC_IMPORT_FORMAT.STANDARD_W_PUBKEY
            oid = encoded[:-1]
        else:  # Standard is defined as "format byte not present"
            f = EC_IMPORT_FORMAT.STANDARD
            oid = encoded

        return cls(alg, CurveOid(oid), f)

    def __bytes__(self) -> bytes:
        buf = struct.pack(">B", self.algorithm_id) + self.oid
        if self.import_format == EC_IMPORT_FORMAT.STANDARD_W_PUBKEY:
            buf += struct.pack(">B", self.import_format)
        return buf


def _parse_key_information(encoded: bytes) -> KeyInformation:
    return {
        KEY_REF(encoded[i]): KEY_STATUS(encoded[i + 1])
        for i in range(0, len(encoded), 2)
    }


def _parse_fingerprints(encoded: bytes) -> Fingerprints:
    slots = list(KEY_REF)
    return {
        slots[i]: encoded[o : o + 20] for i, o in enumerate(range(0, len(encoded), 20))
    }


def _parse_timestamps(encoded: bytes) -> GenerationTimes:
    slots = list(KEY_REF)
    return {
        slots[i]: bytes2int(encoded[o : o + 4])
        for i, o in enumerate(range(0, len(encoded), 4))
    }


@dataclass
class DiscretionaryDataObjects:
    extended_capabilities: ExtendedCapabilities
    attributes_sig: AlgorithmAttributes
    attributes_dec: AlgorithmAttributes
    attributes_aut: AlgorithmAttributes
    attributes_att: AlgorithmAttributes | None
    pw_status: PwStatus
    fingerprints: Fingerprints
    ca_fingerprints: Fingerprints
    generation_times: GenerationTimes
    key_information: KeyInformation
    uif_sig: UIF | None
    uif_dec: UIF | None
    uif_aut: UIF | None
    uif_att: UIF | None

    @classmethod
    def parse(cls, encoded: bytes) -> DiscretionaryDataObjects:
        data = Tlv.parse_dict(encoded)
        return cls(
            ExtendedCapabilities.parse(data[TAG_EXTENDED_CAPABILITIES]),
            AlgorithmAttributes.parse(data[DO.ALGORITHM_ATTRIBUTES_SIG]),
            AlgorithmAttributes.parse(data[DO.ALGORITHM_ATTRIBUTES_DEC]),
            AlgorithmAttributes.parse(data[DO.ALGORITHM_ATTRIBUTES_AUT]),
            (
                AlgorithmAttributes.parse(data[DO.ALGORITHM_ATTRIBUTES_ATT])
                if DO.ALGORITHM_ATTRIBUTES_ATT in data
                else None
            ),
            PwStatus.parse(data[DO.PW_STATUS_BYTES]),
            _parse_fingerprints(data[TAG_FINGERPRINTS]),
            _parse_fingerprints(data[TAG_CA_FINGERPRINTS]),
            _parse_timestamps(data[TAG_GENERATION_TIMES]),
            _parse_key_information(data.get(TAG_KEY_INFORMATION, b"")),
            (UIF.parse(data[DO.UIF_SIG]) if DO.UIF_SIG in data else None),
            (UIF.parse(data[DO.UIF_DEC]) if DO.UIF_DEC in data else None),
            (UIF.parse(data[DO.UIF_AUT]) if DO.UIF_AUT in data else None),
            (UIF.parse(data[DO.UIF_ATT]) if DO.UIF_ATT in data else None),
        )

    def get_algorithm_attributes(self, key_ref: KEY_REF) -> AlgorithmAttributes:
        return getattr(self, f"attributes_{key_ref.name.lower()}")

    def get_uif(self, key_ref: KEY_REF) -> UIF | None:
        return getattr(self, f"uif_{key_ref.name.lower()}")


@dataclass
class ApplicationRelatedData:
    """OpenPGP related data."""

    aid: OpenPgpAid
    historical: bytes
    extended_length_info: ExtendedLengthInfo | None
    general_feature_management: GENERAL_FEATURE_MANAGEMENT | None
    discretionary: DiscretionaryDataObjects

    @classmethod
    def parse(cls, encoded: bytes) -> ApplicationRelatedData:
        outer = Tlv.unpack(DO.APPLICATION_RELATED_DATA, encoded)
        data = Tlv.parse_dict(outer)
        return cls(
            OpenPgpAid(data[DO.AID]),
            data[DO.HISTORICAL_BYTES],
            (
                ExtendedLengthInfo.parse(data[DO.EXTENDED_LENGTH_INFO])
                if DO.EXTENDED_LENGTH_INFO in data
                else None
            ),
            (
                GENERAL_FEATURE_MANAGEMENT(
                    Tlv.unpack(0x81, data[DO.GENERAL_FEATURE_MANAGEMENT])[0]
                )
                if DO.GENERAL_FEATURE_MANAGEMENT in data
                else None
            ),
            # Older keys have data in outer dict
            DiscretionaryDataObjects.parse(data[TAG_DISCRETIONARY] or outer),
        )


@dataclass
class SecuritySupportTemplate:
    signature_counter: int

    @classmethod
    def parse(cls, encoded: bytes) -> SecuritySupportTemplate:
        data = Tlv.parse_dict(Tlv.unpack(DO.SECURITY_SUPPORT_TEMPLATE, encoded))
        return cls(bytes2int(data[TAG_SIGNATURE_COUNTER]))


@dataclass
class Kdf(abc.ABC):
    algorithm: ClassVar[int]

    @abc.abstractmethod
    def process(self, pw: PW, pin: str) -> bytes:
        """Run the KDF on the input PIN."""

    @classmethod
    @abc.abstractmethod
    def _parse_data(cls, data: Mapping[int, bytes]) -> Kdf:
        raise NotImplementedError()

    @classmethod
    def parse(cls, encoded: bytes) -> Kdf:
        data = Tlv.parse_dict(encoded)
        try:
            algorithm = bytes2int(data[0x81])
            for sub in cls.__subclasses__():
                if sub.algorithm == algorithm:
                    return sub._parse_data(data)
        except KeyError:
            pass  # Fall though to KdfNone
        return KdfNone()

    @abc.abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError()


@dataclass
class KdfNone(Kdf):
    algorithm = 0

    @classmethod
    def _parse_data(cls, data) -> KdfNone:
        return cls()

    def process(self, pw, pin):
        return pin.encode()

    def __bytes__(self):
        return Tlv(0x81, struct.pack(">B", self.algorithm))


@unique
class HASH_ALGORITHM(IntEnum):
    SHA256 = 0x08
    SHA512 = 0x0A

    def create_digest(self):
        algorithm = getattr(hashes, self.name)
        return hashes.Hash(algorithm(), default_backend())


@dataclass
class KdfIterSaltedS2k(Kdf):
    algorithm = 3

    hash_algorithm: HASH_ALGORITHM
    iteration_count: int
    salt_user: bytes
    salt_reset: bytes | None
    salt_admin: bytes | None
    initial_hash_user: bytes | None
    initial_hash_admin: bytes | None

    @staticmethod
    def _do_process(hash_algorithm, iteration_count, data):
        # Although the field is called "iteration count", it's actually
        # the number of bytes to be passed to the hash function, which
        # is called only once. Go figure!
        data_count, trailing_bytes = divmod(iteration_count, len(data))
        digest = hash_algorithm.create_digest()
        for _ in range(data_count):
            digest.update(data)
        digest.update(data[:trailing_bytes])
        return digest.finalize()

    @classmethod
    def create(
        cls,
        hash_algorithm: HASH_ALGORITHM = HASH_ALGORITHM.SHA256,
        iteration_count: int = 0x780000,
    ) -> KdfIterSaltedS2k:
        salt_user = os.urandom(8)
        salt_admin = os.urandom(8)
        return cls(
            hash_algorithm,
            iteration_count,
            salt_user,
            os.urandom(8),
            salt_admin,
            cls._do_process(
                hash_algorithm, iteration_count, salt_user + DEFAULT_USER_PIN.encode()
            ),
            cls._do_process(
                hash_algorithm, iteration_count, salt_admin + DEFAULT_ADMIN_PIN.encode()
            ),
        )

    @classmethod
    def _parse_data(cls, data) -> KdfIterSaltedS2k:
        return cls(
            HASH_ALGORITHM(bytes2int(data[0x82])),
            bytes2int(data[0x83]),
            data[0x84],
            data.get(0x85),
            data.get(0x86),
            data.get(0x87),
            data.get(0x88),
        )

    def get_salt(self, pw: PW) -> bytes:
        return getattr(self, f"salt_{pw.name.lower()}")

    def process(self, pw, pin):
        salt = self.get_salt(pw) or self.salt_user
        data = salt + pin.encode()
        return self._do_process(self.hash_algorithm, self.iteration_count, data)

    def __bytes__(self):
        return (
            Tlv(0x81, struct.pack(">B", self.algorithm))
            + Tlv(0x82, struct.pack(">B", self.hash_algorithm))
            + Tlv(0x83, struct.pack(">I", self.iteration_count))
            + Tlv(0x84, self.salt_user)
            + (Tlv(0x85, self.salt_reset) if self.salt_reset else b"")
            + (Tlv(0x86, self.salt_admin) if self.salt_admin else b"")
            + (Tlv(0x87, self.initial_hash_user) if self.initial_hash_user else b"")
            + (Tlv(0x88, self.initial_hash_admin) if self.initial_hash_admin else b"")
        )


@dataclass
class PrivateKeyTemplate(abc.ABC):
    crt: CRT

    def _get_template(self) -> list[Tlv]:
        raise NotImplementedError()

    def __bytes__(self) -> bytes:
        tlvs = self._get_template()
        return Tlv(
            0x4D,
            self.crt
            + Tlv(0x7F48, b"".join(tlv[: -tlv.length] for tlv in tlvs))
            + Tlv(0x5F48, b"".join(tlv.value for tlv in tlvs)),
        )


@dataclass
class RsaKeyTemplate(PrivateKeyTemplate):
    e: bytes
    p: bytes
    q: bytes

    def _get_template(self):
        return [
            Tlv(0x91, self.e),
            Tlv(0x92, self.p),
            Tlv(0x93, self.q),
        ]


@dataclass
class RsaCrtKeyTemplate(RsaKeyTemplate):
    iqmp: bytes
    dmp1: bytes
    dmq1: bytes
    n: bytes

    def _get_template(self):
        return [
            *super()._get_template(),
            Tlv(0x94, self.iqmp),
            Tlv(0x95, self.dmp1),
            Tlv(0x96, self.dmq1),
            Tlv(0x97, self.n),
        ]


@dataclass
class EcKeyTemplate(PrivateKeyTemplate):
    private_key: bytes
    public_key: bytes | None

    def _get_template(self):
        tlvs = [Tlv(0x92, self.private_key)]
        if self.public_key:
            tlvs.append(Tlv(0x99, self.public_key))

        return tlvs


def _get_key_attributes(
    private_key: PrivateKey, key_ref: KEY_REF, version: Version
) -> AlgorithmAttributes:
    if isinstance(private_key, rsa.RSAPrivateKeyWithSerialization):
        if private_key.private_numbers().public_numbers.e != 65537:
            raise ValueError("RSA keys with e != 65537 are not supported!")
        return RsaAttributes.create(
            RSA_SIZE(private_key.key_size),
            (
                RSA_IMPORT_FORMAT.CRT_W_MOD
                if 0 < version[0] < 4
                else RSA_IMPORT_FORMAT.STANDARD
            ),
        )
    return EcAttributes.create(key_ref, OID._from_key(private_key))


def _parse_rsa_key(data: Mapping[int, bytes]) -> rsa.RSAPublicKey:
    numbers = rsa.RSAPublicNumbers(bytes2int(data[0x82]), bytes2int(data[0x81]))
    return numbers.public_key(default_backend())


def _parse_ec_key(oid: CurveOid, data: Mapping[int, bytes]) -> EcPublicKey:
    pubkey_enc = data[0x86]
    if oid == OID.X25519:
        return x25519.X25519PublicKey.from_public_bytes(pubkey_enc)
    if oid == OID.Ed25519:
        return ed25519.Ed25519PublicKey.from_public_bytes(pubkey_enc)

    curve = getattr(ec, oid._get_name())
    return ec.EllipticCurvePublicKey.from_encoded_point(curve(), pubkey_enc)


# Map cryptography hash algorithm to Rust SignHashAlgorithm int value
_HASH_ALGORITHM_MAP: dict[type, int] = {
    type(None): 0,  # SignHashAlgorithm::None
    hashes.SHA1: 1,
    hashes.SHA256: 2,
    hashes.SHA384: 3,
    hashes.SHA512: 4,
}


def _hash_algorithm_to_int(
    hash_algorithm: hashes.HashAlgorithm,
) -> tuple[int, int | None]:
    if isinstance(hash_algorithm, Prehashed):
        inner_type = type(hash_algorithm._algorithm)
        if inner_type not in _HASH_ALGORITHM_MAP:
            raise ValueError(
                f"Unsupported prehash algorithm: {hash_algorithm._algorithm}"
            )
        return 5, _HASH_ALGORITHM_MAP[inner_type]
    ha_type = type(hash_algorithm)
    if ha_type in _HASH_ALGORITHM_MAP:
        return _HASH_ALGORITHM_MAP[ha_type], None
    raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")


def _prepare_private_key_for_native(
    private_key: PrivateKey,
    use_crt: bool = False,
) -> tuple[int, list[bytes]]:
    """Convert a private key to (key_type, components) for the native put_key.

    key_type: 0=RSA, 1=RSA-CRT, 2=EC
    """
    if isinstance(private_key, rsa.RSAPrivateKeyWithSerialization):
        pn = private_key.private_numbers()
        e = int2bytes(pn.public_numbers.e)
        p = int2bytes(pn.p)
        q = int2bytes(pn.q)
        if use_crt:
            iqmp = int2bytes(pn.iqmp)
            dmp1 = int2bytes(pn.dmp1)
            dmq1 = int2bytes(pn.dmq1)
            n = int2bytes(pn.public_numbers.n)
            return (1, [e, p, q, iqmp, dmp1, dmq1, n])
        return (0, [e, p, q])
    elif isinstance(private_key, ec.EllipticCurvePrivateKeyWithSerialization):
        pn = private_key.private_numbers()
        scalar = int2bytes(pn.private_value)
        pub_bytes = private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return (2, [scalar, pub_bytes])
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return (2, [raw, pub])
    elif isinstance(private_key, x25519.X25519PrivateKey):
        raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        raw = raw[::-1]  # X25519 byte order needs to be reversed for the card
        pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return (2, [raw, pub])
    else:
        raise ValueError(f"Unsupported key type: {type(private_key)}")


class OpenPgpSession(Session):
    """A session with the OpenPGP application."""

    def __init__(
        self,
        connection: SmartCardConnection,
        scp_key_params: ScpKeyParams | None = None,
    ):
        native = _NativeOpenPgpSession(connection, scp_key_params)
        self._native = native
        self._version = Version(*native.version)
        self._app_data = ApplicationRelatedData.parse(
            native.get_application_related_data()
        )

        logger.debug(f"OpenPGP session initialized (version={self.version})")

    @property
    def aid(self) -> OpenPgpAid:
        """Get the AID used to select the applet."""
        return self._app_data.aid

    @property
    def version(self) -> Version:
        """Get the firmware version of the key.

        For YubiKey NEO this is the PGP applet version.
        """
        return self._version

    @property
    def extended_capabilities(self) -> ExtendedCapabilities:
        """Get the Extended Capabilities from the YubiKey."""
        return self._app_data.discretionary.extended_capabilities

    def get_challenge(self, length: int) -> bytes:
        """Get random data from the YubiKey.

        :param length: Length of the returned data.
        """
        return bytes(self._native.get_challenge(length))

    def get_data(self, do: DO) -> bytes:
        """Get a Data Object from the YubiKey.

        :param do: The Data Object to get.
        """
        return bytes(self._native.get_data(int(do)))

    def put_data(self, do: DO, data: bytes | SupportsBytes) -> None:
        """Write a Data Object to the YubiKey.

        :param do: The Data Object to write to.
        :param data: The data to write.
        """
        self._native.put_data(int(do), bytes(data))

    def get_pin_status(self) -> PwStatus:
        """Get the current status of PINS."""
        t = self._native.get_pin_status()
        return PwStatus(PIN_POLICY(t[0]), t[1], t[2], t[3], t[4], t[5], t[6])

    def get_signature_counter(self) -> int:
        """Get the number of times the signature key has been used."""
        return self._native.get_signature_counter()

    def get_application_related_data(self) -> ApplicationRelatedData:
        """Read the Application Related Data."""
        raw = self._native.get_application_related_data()
        data = ApplicationRelatedData.parse(raw)
        # Pre 3.0 the UIF is readable separately, but missing from discretionary
        if data.aid.version < (3, 0):
            data.discretionary.uif_sig = self.get_uif(KEY_REF.SIG)
            data.discretionary.uif_dec = self.get_uif(KEY_REF.DEC)
            data.discretionary.uif_aut = self.get_uif(KEY_REF.AUT)
        return data

    def set_signature_pin_policy(self, pin_policy: PIN_POLICY) -> None:
        """Set signature PIN policy.

        Requires Admin PIN verification.

        :param pin_policy: The PIN policy.
        """
        logger.debug(f"Setting Signature PIN policy to {pin_policy}")
        self._native.set_signature_pin_policy(int(pin_policy))
        logger.info("Signature PIN policy set")

    def reset(self) -> None:
        """Perform a factory reset on the OpenPGP application.

        WARNING: This will delete all stored keys, certificates and other data.
        """
        self._native.reset()
        logger.info("OpenPGP application data reset performed")

    def set_pin_attempts(
        self, user_attempts: int, reset_attempts: int, admin_attempts: int
    ) -> None:
        """Set the number of PIN attempts to allow before blocking.

        WARNING: On YubiKey NEO this will reset the PINs to their default values.

        Requires Admin PIN verification.

        :param user_attempts: The User PIN attempts.
        :param reset_attempts: The Reset Code attempts.
        :param admin_attempts: The Admin PIN attempts.
        """
        self._native.set_pin_attempts(user_attempts, reset_attempts, admin_attempts)
        logger.info("Number of PIN attempts has been changed")

    def get_kdf(self) -> Kdf:
        """Get the Key Derivation Function data object."""
        raw = self._native.get_kdf()
        result = Kdf.parse(raw)
        logger.debug(f"Using KDF: {type(result).__name__}")
        return result

    def set_kdf(self, kdf: Kdf) -> None:
        """Set up a PIN Key Derivation Function.

        This enables (or disables) the use of a KDF for PIN verification, as well
        as resetting the User and Admin PINs to their default (initial) values.

        If a Reset Code is present, it will be invalidated.

        This command requires Admin PIN verification.

        :param kdf: The key derivation function.
        """
        self._native.set_kdf(bytes(kdf))
        logger.info("KDF settings changed")

    def verify_pin(self, pin, extended: bool = False):
        """Verify the User PIN.

        This will unlock functionality that requires User PIN verification.
        Note that with `extended=False` (default) only sign operations are allowed.
        Inversely, with `extended=True` sign operations are NOT allowed.

        :param pin: The User PIN.
        :param extended: If `False` only sign operations are allowed,
            otherwise sign operations are NOT allowed.
        """
        logger.debug(f"Verifying User PIN in mode {'82' if extended else '81'}")
        self._native.verify_pin(pin, extended)

    def verify_admin(self, admin_pin):
        """Verify the Admin PIN.

        This will unlock functionality that requires Admin PIN verification.

        :param admin_pin: The Admin PIN.
        """
        logger.debug("Verifying Admin PIN")
        self._native.verify_admin(admin_pin)

    def unverify_pin(self, pw: PW) -> None:
        """Reset verification for PIN.

        :param pw: The User, Admin or Reset PIN
        """
        self._native.unverify_pin(int(pw))

    def change_pin(self, pin: str, new_pin: str) -> None:
        """Change the User PIN.

        :param pin: The current User PIN.
        :param new_pin: The new User PIN.
        """
        self._native.change_pin(pin, new_pin)

    def change_admin(self, admin_pin: str, new_admin_pin: str) -> None:
        """Change the Admin PIN.

        :param admin_pin: The current Admin PIN.
        :param new_admin_pin: The new Admin PIN.
        """
        self._native.change_admin(admin_pin, new_admin_pin)

    def set_reset_code(self, reset_code: str) -> None:
        """Set the Reset Code for User PIN.

        The Reset Code can be used to set a new User PIN if it is lost or becomes
        blocked, using the reset_pin method.

        This command requires Admin PIN verification.

        :param reset_code: The Reset Code for User PIN.
        """
        self._native.set_reset_code(reset_code)
        logger.info("New Reset Code has been set")

    def reset_pin(self, new_pin: str, reset_code: str | None = None) -> None:
        """Reset the User PIN to a new value.

        This command requires Admin PIN verification, or the Reset Code.

        :param new_pin: The new user PIN.
        :param reset_code: The Reset Code.
        """
        self._native.reset_pin(new_pin, reset_code)
        logger.info("New User PIN has been set")

    def get_algorithm_attributes(self, key_ref: KEY_REF) -> AlgorithmAttributes:
        """Get the algorithm attributes for one of the key slots.

        :param key_ref: The key slot.
        """
        logger.debug(f"Getting Algorithm Attributes for {key_ref.name}")
        raw = self._native.get_algorithm_attributes(int(key_ref))
        return AlgorithmAttributes.parse(raw)

    def get_algorithm_information(
        self,
    ) -> Mapping[KEY_REF, Sequence[AlgorithmAttributes]]:
        """Get the list of supported algorithm attributes for each key.

        The return value is a mapping of KEY_REF to a list of supported algorithm
        attributes, which can be set using set_algorithm_attributes.
        """
        raw = self._native.get_algorithm_information()
        return {
            KEY_REF(k): [AlgorithmAttributes.parse(a) for a in v]
            for k, v in raw.items()
        }

    def set_algorithm_attributes(
        self, key_ref: KEY_REF, attributes: AlgorithmAttributes
    ) -> None:
        """Set the algorithm attributes for a key slot.

        WARNING: This will delete any key already stored in the slot if the attributes
        are changed!

        This command requires Admin PIN verification.

        :param key_ref: The key slot.
        :param attributes: The algorithm attributes to set.
        """
        self._native.set_algorithm_attributes(int(key_ref), bytes(attributes))
        logger.info("Algorithm Attributes have been changed")

    def get_uif(self, key_ref: KEY_REF) -> UIF:
        """Get the User Interaction Flag (touch requirement) for a key.

        :param key_ref: The key slot.
        """
        return UIF(self._native.get_uif(int(key_ref)))

    def set_uif(self, key_ref: KEY_REF, uif: UIF) -> None:
        """Set the User Interaction Flag (touch requirement) for a key.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param uif: The User Interaction Flag.
        """
        self._native.set_uif(int(key_ref), int(uif))
        logger.info(f"UIF changed for {key_ref.name}")

    def get_key_information(self) -> KeyInformation:
        """Get the status of the keys."""
        logger.debug("Getting Key Information")
        raw = self._native.get_key_information()
        return {KEY_REF(k): KEY_STATUS(v) for k, v in raw.items()}

    def get_generation_times(self) -> GenerationTimes:
        """Get timestamps for when keys were generated."""
        logger.debug("Getting key generation timestamps")
        raw = self._native.get_generation_times()
        return {KEY_REF(k): v for k, v in raw.items()}

    def set_generation_time(self, key_ref: KEY_REF, timestamp: int) -> None:
        """Set the generation timestamp for a key.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param timestamp: The timestamp.
        """
        logger.debug(f"Setting key generation timestamp for {key_ref.name}")
        self._native.set_generation_time(int(key_ref), timestamp)
        logger.info(f"Key generation timestamp set for {key_ref.name}")

    def get_fingerprints(self) -> Fingerprints:
        """Get key fingerprints."""
        logger.debug("Getting key fingerprints")
        raw = self._native.get_fingerprints()
        return {KEY_REF(k): bytes(v) for k, v in raw.items()}

    def set_fingerprint(self, key_ref: KEY_REF, fingerprint: bytes) -> None:
        """Set the fingerprint for a key.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param fingerprint: The fingerprint.
        """
        logger.debug(f"Setting key fingerprint for {key_ref.name}")
        self._native.set_fingerprint(int(key_ref), fingerprint)
        logger.info(f"Key fingerprint set for {key_ref.name}")

    def get_public_key(self, key_ref: KEY_REF) -> PublicKey:
        """Get the public key from a slot.

        :param key_ref: The key slot.
        """
        logger.debug(f"Getting public key for {key_ref.name}")
        raw = self._native.get_public_key(int(key_ref))
        data = Tlv.parse_dict(raw)
        attributes = self.get_algorithm_attributes(key_ref)
        if isinstance(attributes, EcAttributes):
            return _parse_ec_key(attributes.oid, data)
        else:
            return _parse_rsa_key(data)

    def generate_rsa_key(
        self, key_ref: KEY_REF, key_size: RSA_SIZE
    ) -> rsa.RSAPublicKey:
        """Generate an RSA key in the given slot.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param key_size: The size of the RSA key.
        """
        raw = self._native.generate_rsa_key(int(key_ref), int(key_size))
        data = Tlv.parse_dict(raw)
        logger.info(f"RSA key generated for {key_ref.name}")
        return _parse_rsa_key(data)

    def generate_ec_key(self, key_ref: KEY_REF, curve_oid: CurveOid) -> EcPublicKey:
        """Generate an EC key in the given slot.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param curve_oid: The curve OID.
        """
        raw = self._native.generate_ec_key(int(key_ref), curve_oid.dotted_string)
        data = Tlv.parse_dict(raw)
        logger.info(f"EC key generated for {key_ref.name}")
        return _parse_ec_key(curve_oid, data)

    def put_key(self, key_ref: KEY_REF, private_key: PrivateKey) -> None:
        """Import a private key into the given slot.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param private_key: The private key to import.
        """

        logger.debug(f"Importing a private key for {key_ref.name}")
        attributes = _get_key_attributes(private_key, key_ref, self.version)
        if (
            EXTENDED_CAPABILITY_FLAGS.ALGORITHM_ATTRIBUTES_CHANGEABLE
            in self.extended_capabilities.flags
        ):
            self.set_algorithm_attributes(key_ref, attributes)
        else:
            if not (
                isinstance(attributes, RsaAttributes)
                and attributes.n_len == RSA_SIZE.RSA2048
            ):
                raise NotSupportedError("This YubiKey only supports RSA 2048 keys")

        use_crt = 0 < self.version[0] < 4
        key_type, components = _prepare_private_key_for_native(private_key, use_crt)
        self._native.put_key(int(key_ref), key_type, components)
        logger.info(f"Private key imported for {key_ref.name}")

    def delete_key(self, key_ref: KEY_REF) -> None:
        """Delete the contents of a key slot.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        """
        self._native.delete_key(int(key_ref))

    def get_certificate(self, key_ref: KEY_REF) -> x509.Certificate:
        """Get a certificate from a slot.

        :param key_ref: The slot.
        """
        logger.debug(f"Getting certificate for key {key_ref.name}")
        der = self._native.get_certificate(int(key_ref))
        if not der:
            raise ValueError("No certificate found!")
        return x509.load_der_x509_certificate(bytes(der), default_backend())

    def put_certificate(self, key_ref: KEY_REF, certificate: x509.Certificate) -> None:
        """Import a certificate into a slot.

        Requires Admin PIN verification.

        :param key_ref: The slot.
        :param certificate: The X.509 certificate to import.
        """
        cert_data = certificate.public_bytes(Encoding.DER)
        logger.debug(f"Importing certificate for key {key_ref.name}")
        self._native.put_certificate(int(key_ref), cert_data)
        logger.info(f"Certificate imported for key {key_ref.name}")

    def delete_certificate(self, key_ref: KEY_REF) -> None:
        """Delete a certificate in a slot.

        Requires Admin PIN verification.

        :param key_ref: The slot.
        """
        logger.debug(f"Deleting certificate for key {key_ref.name}")
        self._native.delete_certificate(int(key_ref))
        logger.info(f"Certificate deleted for key {key_ref.name}")

    def attest_key(self, key_ref: KEY_REF) -> x509.Certificate:
        """Create an attestation certificate for a key.

        The certificate is written to the certificate slot for the key, and its
        content is returned.

        Requires User PIN verification.

        :param key_ref: The key slot.
        """
        der = self._native.attest_key(int(key_ref))
        logger.info(f"Attestation certificate created for {key_ref.name}")
        return x509.load_der_x509_certificate(bytes(der), default_backend())

    def sign(self, message: bytes, hash_algorithm: hashes.HashAlgorithm) -> bytes:
        """Sign a message using the SIG key.

        Requires User PIN verification.

        :param message: The message to sign.
        :param hash_algorithm: The pre-signature hash algorithm.
        """
        ha_int, prehash = _hash_algorithm_to_int(hash_algorithm)
        response = bytes(self._native.sign(message, ha_int, prehash))
        attributes = self.get_algorithm_attributes(KEY_REF.SIG)
        logger.info("Message signed")
        if attributes.algorithm_id == 0x13:
            ln = len(response) // 2
            return encode_dss_signature(
                int.from_bytes(response[:ln], "big"),
                int.from_bytes(response[ln:], "big"),
            )
        return response

    def decrypt(self, value: bytes | EcPublicKey) -> bytes:
        """Decrypt a value using the DEC key.

        For RSA the `value` should be an encrypted block.
        For ECDH the `value` should be a peer public-key to perform the key exchange
        with, and the result will be the derived shared secret.

        Requires (extended) User PIN verification.

        :param value: The value to decrypt.
        """
        if isinstance(value, ec.EllipticCurvePublicKey):
            data = value.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        elif isinstance(value, x25519.X25519PublicKey):
            data = value.public_bytes(Encoding.Raw, PublicFormat.Raw)
        elif isinstance(value, bytes):
            data = value
        else:
            raise ValueError("Value must be a bytes or public key")
        response = bytes(self._native.decrypt(data))
        logger.info("Value decrypted")
        return response

    def authenticate(
        self, message: bytes, hash_algorithm: hashes.HashAlgorithm
    ) -> bytes:
        """Authenticate a message using the AUT key.

        Requires User PIN verification.

        :param message: The message to authenticate.
        :param hash_algorithm: The pre-authentication hash algorithm.
        """
        ha_int, prehash = _hash_algorithm_to_int(hash_algorithm)
        response = bytes(self._native.authenticate(message, ha_int, prehash))
        attributes = self.get_algorithm_attributes(KEY_REF.AUT)
        logger.info("Message authenticated")
        if attributes.algorithm_id == 0x13:
            ln = len(response) // 2
            return encode_dss_signature(
                int.from_bytes(response[:ln], "big"),
                int.from_bytes(response[ln:], "big"),
            )
        return response
