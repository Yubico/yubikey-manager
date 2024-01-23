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
    Tlv,
    Version,
    NotSupportedError,
    InvalidPinError,
    require_version,
    int2bytes,
    bytes2int,
)
from .core.smartcard import (
    SmartCardConnection,
    SmartCardProtocol,
    ApduFormat,
    ApduError,
    AID,
    SW,
)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

import os
import abc
from enum import Enum, IntEnum, IntFlag, unique
from dataclasses import dataclass
from typing import (
    Optional,
    Tuple,
    ClassVar,
    Mapping,
    Sequence,
    SupportsBytes,
    Union,
    Dict,
    List,
)
import struct
import logging

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
TAG_PUBLIC_KEY = 0x7F49


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
    def version(self) -> Tuple[int, int]:
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
    def parse(cls, encoded) -> "CardholderRelatedData":
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
    def parse(cls, encoded) -> "ExtendedLengthInfo":
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
    def parse(cls, encoded: bytes) -> "ExtendedCapabilities":
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
    def parse(cls, encoded: bytes) -> "PwStatus":
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
EcPublicKey = Union[
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    x25519.X25519PublicKey,
]
PublicKey = Union[EcPublicKey, rsa.RSAPublicKey]
EcPrivateKey = Union[
    ec.EllipticCurvePrivateKeyWithSerialization,
    ed25519.Ed25519PrivateKey,
    x25519.X25519PrivateKey,
]
PrivateKey = Union[
    rsa.RSAPrivateKeyWithSerialization,
    EcPrivateKey,
]


# mypy doesn't handle abstract dataclasses well
@dataclass  # type: ignore[misc]
class AlgorithmAttributes(abc.ABC):
    """OpenPGP key algorithm attributes."""

    _supported_ids: ClassVar[Sequence[int]]
    algorithm_id: int

    @classmethod
    def parse(cls, encoded: bytes) -> "AlgorithmAttributes":
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
    def _parse_data(cls, alg: int, encoded: bytes) -> "AlgorithmAttributes":
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
    ) -> "RsaAttributes":
        return cls(0x01, n_len, 17, import_format)

    @classmethod
    def _parse_data(cls, alg, encoded) -> "RsaAttributes":
        n, e, f = struct.unpack(">HHB", encoded)
        return cls(alg, n, e, RSA_IMPORT_FORMAT(f))

    def __bytes__(self) -> bytes:
        return struct.pack(
            ">BHHB", self.algorithm_id, self.n_len, self.e_len, self.import_format
        )


class CurveOid(bytes):
    def _get_name(self) -> str:
        for oid in OID:
            if self.startswith(oid):
                return oid.name
        return "Unknown Curve"

    def __str__(self) -> str:
        return self._get_name()

    def __repr__(self) -> str:
        name = self._get_name()
        return f"{name}({self.hex()})"


class OID(CurveOid, Enum):
    SECP256R1 = CurveOid(b"\x2a\x86\x48\xce\x3d\x03\x01\x07")
    SECP256K1 = CurveOid(b"\x2b\x81\x04\x00\x0a")
    SECP384R1 = CurveOid(b"\x2b\x81\x04\x00\x22")
    SECP521R1 = CurveOid(b"\x2b\x81\x04\x00\x23")
    BrainpoolP256R1 = CurveOid(b"\x2b\x24\x03\x03\x02\x08\x01\x01\x07")
    BrainpoolP384R1 = CurveOid(b"\x2b\x24\x03\x03\x02\x08\x01\x01\x0b")
    BrainpoolP512R1 = CurveOid(b"\x2b\x24\x03\x03\x02\x08\x01\x01\x0d")
    X25519 = CurveOid(b"\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01")
    Ed25519 = CurveOid(b"\x2b\x06\x01\x04\x01\xda\x47\x0f\x01")

    @classmethod
    def _from_key(cls, private_key: EcPrivateKey) -> CurveOid:
        name = ""
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
    def create(cls, key_ref: KEY_REF, oid: CurveOid) -> "EcAttributes":
        if oid == OID.Ed25519:
            alg = 0x16  # EdDSA
        elif key_ref == KEY_REF.DEC:
            alg = 0x12  # ECDH
        else:
            alg = 0x13  # ECDSA
        return cls(alg, oid, EC_IMPORT_FORMAT.STANDARD)

    @classmethod
    def _parse_data(cls, alg, encoded) -> "EcAttributes":
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
    attributes_att: Optional[AlgorithmAttributes]
    pw_status: PwStatus
    fingerprints: Fingerprints
    ca_fingerprints: Fingerprints
    generation_times: GenerationTimes
    key_information: KeyInformation
    uif_sig: Optional[UIF]
    uif_dec: Optional[UIF]
    uif_aut: Optional[UIF]
    uif_att: Optional[UIF]

    @classmethod
    def parse(cls, encoded: bytes) -> "DiscretionaryDataObjects":
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


@dataclass
class ApplicationRelatedData:
    """OpenPGP related data."""

    aid: OpenPgpAid
    historical: bytes
    extended_length_info: Optional[ExtendedLengthInfo]
    general_feature_management: Optional[GENERAL_FEATURE_MANAGEMENT]
    discretionary: DiscretionaryDataObjects

    @classmethod
    def parse(cls, encoded: bytes) -> "ApplicationRelatedData":
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
    def parse(cls, encoded: bytes) -> "SecuritySupportTemplate":
        data = Tlv.parse_dict(Tlv.unpack(DO.SECURITY_SUPPORT_TEMPLATE, encoded))
        return cls(bytes2int(data[TAG_SIGNATURE_COUNTER]))


# mypy doesn't handle abstract dataclasses well
@dataclass  # type: ignore[misc]
class Kdf(abc.ABC):
    algorithm: ClassVar[int]

    @abc.abstractmethod
    def process(self, pw: PW, pin: str) -> bytes:
        """Run the KDF on the input PIN."""

    @classmethod
    @abc.abstractmethod
    def _parse_data(cls, data: Mapping[int, bytes]) -> "Kdf":
        raise NotImplementedError()

    @classmethod
    def parse(cls, encoded: bytes) -> "Kdf":
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
    def _parse_data(cls, data) -> "KdfNone":
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
    salt_reset: bytes
    salt_admin: bytes
    initial_hash_user: Optional[bytes]
    initial_hash_admin: Optional[bytes]

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
    ) -> "KdfIterSaltedS2k":
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
    def _parse_data(cls, data) -> "KdfIterSaltedS2k":
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


# mypy doesn't handle abstract dataclasses well
@dataclass  # type: ignore[misc]
class PrivateKeyTemplate(abc.ABC):
    crt: CRT

    def _get_template(self) -> Sequence[Tlv]:
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
        return (
            Tlv(0x91, self.e),
            Tlv(0x92, self.p),
            Tlv(0x93, self.q),
        )


@dataclass
class RsaCrtKeyTemplate(RsaKeyTemplate):
    iqmp: bytes
    dmp1: bytes
    dmq1: bytes
    n: bytes

    def _get_template(self):
        return (
            *super()._get_template(),
            Tlv(0x94, self.iqmp),
            Tlv(0x95, self.dmp1),
            Tlv(0x96, self.dmq1),
            Tlv(0x97, self.n),
        )


@dataclass
class EcKeyTemplate(PrivateKeyTemplate):
    private_key: bytes
    public_key: Optional[bytes]

    def _get_template(self):
        tlvs: Tuple[Tlv, ...] = (Tlv(0x92, self.private_key),)
        if self.public_key:
            tlvs = (*tlvs, Tlv(0x99, self.public_key))

        return tlvs


def _get_key_attributes(
    private_key: PrivateKey, key_ref: KEY_REF, version: Version
) -> AlgorithmAttributes:
    if isinstance(private_key, rsa.RSAPrivateKeyWithSerialization):
        if private_key.private_numbers().public_numbers.e != 65537:
            raise ValueError("RSA keys with e != 65537 are not supported!")
        return RsaAttributes.create(
            RSA_SIZE(private_key.key_size),
            RSA_IMPORT_FORMAT.CRT_W_MOD
            if 0 < version[0] < 4
            else RSA_IMPORT_FORMAT.STANDARD,
        )
    return EcAttributes.create(key_ref, OID._from_key(private_key))


def _get_key_template(
    private_key: PrivateKey, key_ref: KEY_REF, use_crt: bool = False
) -> PrivateKeyTemplate:
    if isinstance(private_key, rsa.RSAPrivateKeyWithSerialization):
        rsa_numbers = private_key.private_numbers()
        ln = (private_key.key_size // 8) // 2

        e = b"\x01\x00\x01"  # e=65537
        p = int2bytes(rsa_numbers.p, ln)
        q = int2bytes(rsa_numbers.q, ln)
        if not use_crt:
            return RsaKeyTemplate(key_ref.crt, e, p, q)
        else:
            dp = int2bytes(rsa_numbers.dmp1, ln)
            dq = int2bytes(rsa_numbers.dmq1, ln)
            qinv = int2bytes(rsa_numbers.iqmp, ln)
            n = int2bytes(rsa_numbers.public_numbers.n, 2 * ln)
            return RsaCrtKeyTemplate(key_ref.crt, e, p, q, qinv, dp, dq, n)

    elif isinstance(private_key, ec.EllipticCurvePrivateKeyWithSerialization):
        ec_numbers = private_key.private_numbers()
        ln = private_key.key_size // 8
        return EcKeyTemplate(key_ref.crt, int2bytes(ec_numbers.private_value, ln), None)

    elif isinstance(private_key, (ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey)):
        pkb = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        if isinstance(private_key, x25519.X25519PrivateKey):
            pkb = pkb[::-1]  # byte order needs to be reversed
        return EcKeyTemplate(
            key_ref.crt,
            pkb,
            None,
        )

    raise ValueError("Unsupported key type")


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


_pkcs1v15_headers = {
    hashes.MD5: bytes.fromhex("3020300C06082A864886F70D020505000410"),
    hashes.SHA1: bytes.fromhex("3021300906052B0E03021A05000414"),
    hashes.SHA224: bytes.fromhex("302D300D06096086480165030402040500041C"),
    hashes.SHA256: bytes.fromhex("3031300D060960864801650304020105000420"),
    hashes.SHA384: bytes.fromhex("3041300D060960864801650304020205000430"),
    hashes.SHA512: bytes.fromhex("3051300D060960864801650304020305000440"),
    hashes.SHA512_224: bytes.fromhex("302D300D06096086480165030402050500041C"),
    hashes.SHA512_256: bytes.fromhex("3031300D060960864801650304020605000420"),
}


def _pad_message(attributes, message, hash_algorithm):
    if attributes.algorithm_id == 0x16:  # EdDSA, never hash
        return message

    if isinstance(hash_algorithm, Prehashed):
        hashed = message
    else:
        h = hashes.Hash(hash_algorithm, default_backend())
        h.update(message)
        hashed = h.finalize()

    if isinstance(attributes, EcAttributes):
        return hashed
    if isinstance(attributes, RsaAttributes):
        try:
            return _pkcs1v15_headers[type(hash_algorithm)] + hashed
        except KeyError:
            raise ValueError(f"Unsupported hash algorithm for RSA: {hash_algorithm}")


class OpenPgpSession:
    """A session with the OpenPGP application."""

    def __init__(self, connection: SmartCardConnection):
        self.protocol = SmartCardProtocol(connection)
        try:
            self.protocol.select(AID.OPENPGP)
        except ApduError as e:
            if e.sw in (SW.NO_INPUT_DATA, SW.CONDITIONS_NOT_SATISFIED):
                # Not activated, activate
                logger.warning("Application not active, sending ACTIVATE")
                self.protocol.send_apdu(0, INS.ACTIVATE, 0, 0)
                self.protocol.select(AID.OPENPGP)
            else:
                raise
        self._version = self._read_version()

        self.protocol.enable_touch_workaround(self.version)
        if not 0 < self.version[0] < 4:
            self.protocol.apdu_format = ApduFormat.EXTENDED

        # Note: This value is cached!
        # Do not rely on contained information that can change!
        self._app_data = self.get_application_related_data()
        logger.debug(f"OpenPGP session initialized (version={self.version})")

    def _read_version(self) -> Version:
        logger.debug("Getting version number")
        bcd = self.protocol.send_apdu(0, INS.GET_VERSION, 0, 0)
        return Version(*(_bcd(x) for x in bcd))

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
        e = self.extended_capabilities
        if EXTENDED_CAPABILITY_FLAGS.GET_CHALLENGE not in e.flags:
            raise NotSupportedError("GET_CHALLENGE is not supported")
        if not 0 < length <= e.challenge_max_length:
            raise NotSupportedError("Unsupported challenge length")

        logger.debug(f"Getting {length} random bytes")
        return self.protocol.send_apdu(0, INS.GET_CHALLENGE, 0, 0, le=length)

    def get_data(self, do: DO) -> bytes:
        """Get a Data Object from the YubiKey.

        :param do: The Data Object to get.
        """
        logger.debug(f"Reading Data Object {do.name} ({do:X})")
        return self.protocol.send_apdu(0, INS.GET_DATA, do >> 8, do & 0xFF)

    def put_data(self, do: DO, data: Union[bytes, SupportsBytes]) -> None:
        """Write a Data Object to the YubiKey.

        :param do: The Data Object to write to.
        :param data: The data to write.
        """
        self.protocol.send_apdu(0, INS.PUT_DATA, do >> 8, do & 0xFF, bytes(data))
        logger.info(f"Wrote Data Object {do.name} ({do:X})")

    def get_pin_status(self) -> PwStatus:
        """Get the current status of PINS."""
        return PwStatus.parse(self.get_data(DO.PW_STATUS_BYTES))

    def get_signature_counter(self) -> int:
        """Get the number of times the signature key has been used."""
        s = SecuritySupportTemplate.parse(self.get_data(DO.SECURITY_SUPPORT_TEMPLATE))
        return s.signature_counter

    def get_application_related_data(self) -> ApplicationRelatedData:
        """Read the Application Related Data."""
        return ApplicationRelatedData.parse(self.get_data(DO.APPLICATION_RELATED_DATA))

    def set_signature_pin_policy(self, pin_policy: PIN_POLICY) -> None:
        """Set signature PIN policy.

        Requires Admin PIN verification.

        :param pin_policy: The PIN policy.
        """
        logger.debug(f"Setting Signature PIN policy to {pin_policy}")
        data = struct.pack(">B", pin_policy)
        self.put_data(DO.PW_STATUS_BYTES, data)
        logger.info("Signature PIN policy set")

    def reset(self) -> None:
        """Perform a factory reset on the OpenPGP application.

        WARNING: This will delete all stored keys, certificates and other data.
        """
        require_version(self.version, (1, 0, 6))
        logger.debug("Preparing OpenPGP reset")

        # Ensure the User and Admin PINs are blocked
        status = self.get_pin_status()
        for pw in (PW.USER, PW.ADMIN):
            logger.debug(f"Verify {pw.name} PIN with invalid attempts until blocked")
            for _ in range(status.get_attempts(pw)):
                try:
                    self.protocol.send_apdu(0, INS.VERIFY, 0, pw, _INVALID_PIN)
                except ApduError:
                    pass

        # Reset the application
        logger.debug("Sending TERMINATE, then ACTIVATE")
        self.protocol.send_apdu(0, INS.TERMINATE, 0, 0)
        self.protocol.send_apdu(0, INS.ACTIVATE, 0, 0)

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
        if self.version[0] == 1:
            # YubiKey NEO
            require_version(self.version, (1, 0, 7))
        else:
            require_version(self.version, (4, 3, 1))

        attempts = (user_attempts, reset_attempts, admin_attempts)
        logger.debug(f"Setting PIN attempts to {attempts}")
        self.protocol.send_apdu(
            0,
            INS.SET_PIN_RETRIES,
            0,
            0,
            struct.pack(">BBB", *attempts),
        )
        logger.info("Number of PIN attempts has been changed")

    def get_kdf(self) -> Kdf:
        """Get the Key Derivation Function data object."""
        if EXTENDED_CAPABILITY_FLAGS.KDF not in self.extended_capabilities.flags:
            kdf: Kdf = KdfNone()
        else:
            kdf = Kdf.parse(self.get_data(DO.KDF))
        logger.debug(f"Using KDF: {type(kdf).__name__}")
        return kdf

    def set_kdf(self, kdf: Kdf) -> None:
        """Set up a PIN Key Derivation Function.

        This enables (or disables) the use of a KDF for PIN verification, as well
        as resetting the User and Admin PINs to their default (initial) values.

        If a Reset Code is present, it will be invalidated.

        This command requires Admin PIN verification.

        :param kdf: The key derivation function.
        """
        e = self._app_data.discretionary.extended_capabilities
        if EXTENDED_CAPABILITY_FLAGS.KDF not in e.flags:
            raise NotSupportedError("KDF is not supported")

        logger.debug(f"Setting PIN KDF to algorithm: {kdf.algorithm}")
        self.put_data(DO.KDF, kdf)
        logger.info("KDF settings changed")

    def _process_pin(self, kdf: Kdf, pw: PW, pin: str) -> bytes:
        pin_bytes = kdf.process(pw, pin)
        pin_len = len(pin_bytes)
        min_len = 6 if pw is PW.USER else 8
        max_len = self._app_data.discretionary.pw_status.get_max_len(pw)
        if not (min_len <= pin_len <= max_len):
            raise ValueError(
                f"{pw.name} PIN length must be in the range {min_len}-{max_len}"
            )
        return pin_bytes

    def _verify(self, pw: PW, pin: str, mode: int = 0) -> None:
        pin_enc = self._process_pin(self.get_kdf(), pw, pin)
        try:
            self.protocol.send_apdu(0, INS.VERIFY, 0, pw + mode, pin_enc)
        except ApduError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                attempts = self.get_pin_status().get_attempts(pw)
                raise InvalidPinError(attempts)
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise InvalidPinError(0, f"{pw.name} PIN blocked")
            raise e

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
        self._verify(PW.USER, pin, 1 if extended else 0)

    def verify_admin(self, admin_pin):
        """Verify the Admin PIN.

        This will unlock functionality that requires Admin PIN verification.

        :param admin_pin: The Admin PIN.
        """
        logger.debug("Verifying Admin PIN")
        self._verify(PW.ADMIN, admin_pin)

    def unverify_pin(self, pw: PW) -> None:
        """Reset verification for PIN.

        :param pw: The User, Admin or Reset PIN
        """
        require_version(self.version, (5, 6, 0))
        logger.debug(f"Resetting verification for {pw.name} PIN")
        self.protocol.send_apdu(0, INS.VERIFY, 0xFF, pw)

    def _change(self, pw: PW, pin: str, new_pin: str) -> None:
        logger.debug(f"Changing {pw.name} PIN")
        kdf = self.get_kdf()
        try:
            self.protocol.send_apdu(
                0,
                INS.CHANGE_PIN,
                0,
                pw,
                self._process_pin(kdf, pw, pin) + self._process_pin(kdf, pw, new_pin),
            )
        except ApduError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                attempts = self.get_pin_status().get_attempts(pw)
                raise InvalidPinError(attempts)
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise InvalidPinError(0, f"{pw.name} PIN blocked")
            raise e

        logger.info(f"New {pw.name} PIN set")

    def change_pin(self, pin: str, new_pin: str) -> None:
        """Change the User PIN.

        :param pin: The current User PIN.
        :param new_pin: The new User PIN.
        """
        self._change(PW.USER, pin, new_pin)

    def change_admin(self, admin_pin: str, new_admin_pin: str) -> None:
        """Change the Admin PIN.

        :param admin_pin: The current Admin PIN.
        :param new_admin_pin: The new Admin PIN.
        """
        self._change(PW.ADMIN, admin_pin, new_admin_pin)

    def set_reset_code(self, reset_code: str) -> None:
        """Set the Reset Code for User PIN.

        The Reset Code can be used to set a new User PIN if it is lost or becomes
        blocked, using the reset_pin method.

        This command requires Admin PIN verification.

        :param reset_code: The Reset Code for User PIN.
        """
        logger.debug("Setting a new PIN Reset Code")
        data = self._process_pin(self.get_kdf(), PW.RESET, reset_code)
        self.put_data(DO.RESETTING_CODE, data)
        logger.info("New Reset Code has been set")

    def reset_pin(self, new_pin: str, reset_code: Optional[str] = None) -> None:
        """Reset the User PIN to a new value.

        This command requires Admin PIN verification, or the Reset Code.

        :param new_pin: The new user PIN.
        :param reset_code: The Reset Code.
        """
        logger.debug("Resetting User PIN")
        kdf = self.get_kdf()
        data = self._process_pin(kdf, PW.USER, new_pin)
        if reset_code:
            logger.debug("Using Reset Code")
            data = self._process_pin(kdf, PW.RESET, reset_code) + data
            p1 = 0
        else:
            p1 = 2

        try:
            self.protocol.send_apdu(0, INS.RESET_RETRY_COUNTER, p1, PW.USER, data)
        except ApduError as e:
            if reset_code:
                if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                    attempts = self.get_pin_status().attempts_reset
                    raise InvalidPinError(
                        attempts, f"Invalid Reset Code, {attempts} remaining"
                    )
                if e.sw in (SW.AUTH_METHOD_BLOCKED, SW.INCORRECT_PARAMETERS):
                    raise InvalidPinError(0, "Reset Code blocked")
            raise e
        logger.info("New User PIN has been set")

    def get_algorithm_attributes(self, key_ref: KEY_REF) -> AlgorithmAttributes:
        """Get the algorithm attributes for one of the key slots.

        :param key_ref: The key slot.
        """
        logger.debug(f"Getting Algorithm Attributes for {key_ref.name}")
        data = self.get_application_related_data()
        return data.discretionary.get_algorithm_attributes(key_ref)

    def get_algorithm_information(
        self,
    ) -> Mapping[KEY_REF, Sequence[AlgorithmAttributes]]:
        """Get the list of supported algorithm attributes for each key.

        The return value is a mapping of KEY_REF to a list of supported algorithm
        attributes, which can be set using set_algorithm_attributes.
        """
        if (
            EXTENDED_CAPABILITY_FLAGS.ALGORITHM_ATTRIBUTES_CHANGEABLE
            not in self.extended_capabilities.flags
        ):
            raise NotSupportedError("Writing Algorithm Attributes is not supported")

        if self.version < (5, 2, 0) and self.version[0] > 0:
            sizes = [RSA_SIZE.RSA2048]
            if 0 < self.version[0] < 4:  # Neo needs CRT
                fmt = RSA_IMPORT_FORMAT.CRT_W_MOD
            else:
                fmt = RSA_IMPORT_FORMAT.STANDARD
                if self.version[:2] != (4, 4):  # Non-FIPS
                    sizes.extend([RSA_SIZE.RSA3072, RSA_SIZE.RSA4096])
            return {
                KEY_REF.SIG: [RsaAttributes.create(size, fmt) for size in sizes],
                KEY_REF.DEC: [RsaAttributes.create(size, fmt) for size in sizes],
                KEY_REF.AUT: [RsaAttributes.create(size, fmt) for size in sizes],
            }

        logger.debug("Getting supported Algorithm Information")
        buf = self.get_data(DO.ALGORITHM_INFORMATION)
        try:
            buf = Tlv.unpack(DO.ALGORITHM_INFORMATION, buf)
        except ValueError:
            buf = Tlv.unpack(DO.ALGORITHM_INFORMATION, buf + b"\0\0")[:-2]

        slots = {slot.algorithm_attributes_do: slot for slot in KEY_REF}
        data: Dict[KEY_REF, List[AlgorithmAttributes]] = {}
        for tlv in Tlv.parse_list(buf):
            data.setdefault(slots[DO(tlv.tag)], []).append(
                AlgorithmAttributes.parse(tlv.value)
            )

        if self.version < (5, 6, 1) and self.version[0] > 0:
            # Fix for invalid Curve25519 entries:
            # Remove X25519 with EdDSA from all keys
            invalid_x25519 = EcAttributes(0x16, OID.X25519, EC_IMPORT_FORMAT.STANDARD)
            for values in data.values():
                values.remove(invalid_x25519)
            x25519 = EcAttributes(0x12, OID.X25519, EC_IMPORT_FORMAT.STANDARD)
            # Add X25519 ECDH for DEC
            if x25519 not in data[KEY_REF.DEC]:
                data[KEY_REF.DEC].append(x25519)
            # Remove EdDSA from DEC, ATT
            ed25519_attr = EcAttributes(0x16, OID.Ed25519, EC_IMPORT_FORMAT.STANDARD)
            data[KEY_REF.DEC].remove(ed25519_attr)
            data[KEY_REF.ATT].remove(ed25519_attr)

        return data

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
        logger.debug(f"Setting Algorithm Attributes for {key_ref.name}")
        supported = self.get_algorithm_information()
        if self.version[0] > 0:  # Don't check support on major version 0
            if key_ref not in supported:
                raise NotSupportedError("Key slot not supported")
            if attributes not in supported[key_ref]:
                raise NotSupportedError("Algorithm attributes not supported")

        self.put_data(key_ref.algorithm_attributes_do, attributes)
        logger.info("Algorithm Attributes have been changed")

    def get_uif(self, key_ref: KEY_REF) -> UIF:
        """Get the User Interaction Flag (touch requirement) for a key.

        :param key_ref: The key slot.
        """
        try:
            return UIF.parse(self.get_data(key_ref.uif_do))
        except ApduError as e:
            if e.sw == SW.WRONG_PARAMETERS_P1P2:
                # Not supported
                return UIF.OFF
            raise

    def set_uif(self, key_ref: KEY_REF, uif: UIF) -> None:
        """Set the User Interaction Flag (touch requirement) for a key.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param uif: The User Interaction Flag.
        """
        require_version(self.version, (4, 2, 0))
        if key_ref == KEY_REF.ATT:
            require_version(
                self.version,
                (5, 2, 1),
                "Attestation key requires YubiKey 5.2.1 or later.",
            )
        if uif.is_cached:
            require_version(
                self.version,
                (5, 2, 1),
                "Cached UIF values require YubiKey 5.2.1 or later.",
            )

        logger.debug(f"Setting UIF for {key_ref.name} to {uif.name}")
        if self.get_uif(key_ref).is_fixed:
            raise ValueError("Cannot change UIF when set to FIXED.")

        self.put_data(key_ref.uif_do, uif)
        logger.info(f"UIF changed for {key_ref.name}")

    def get_key_information(self) -> KeyInformation:
        """Get the status of the keys."""
        logger.debug("Getting Key Information")
        return self.get_application_related_data().discretionary.key_information

    def get_generation_times(self) -> GenerationTimes:
        """Get timestamps for when keys were generated."""
        logger.debug("Getting key generation timestamps")
        return self.get_application_related_data().discretionary.generation_times

    def set_generation_time(self, key_ref: KEY_REF, timestamp: int) -> None:
        """Set the generation timestamp for a key.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param timestamp: The timestamp.
        """
        logger.debug(f"Setting key generation timestamp for {key_ref.name}")
        self.put_data(key_ref.generation_time_do, struct.pack(">I", timestamp))
        logger.info(f"Key generation timestamp set for {key_ref.name}")

    def get_fingerprints(self) -> Fingerprints:
        """Get key fingerprints."""
        logger.debug("Getting key fingerprints")
        return self.get_application_related_data().discretionary.fingerprints

    def set_fingerprint(self, key_ref: KEY_REF, fingerprint: bytes) -> None:
        """Set the fingerprint for a key.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param fingerprint: The fingerprint.
        """
        logger.debug(f"Setting key fingerprint for {key_ref.name}")
        self.put_data(key_ref.fingerprint_do, fingerprint)
        logger.info("Key fingerprint set for {key_ref.name}")

    def get_public_key(self, key_ref: KEY_REF) -> PublicKey:
        """Get the public key from a slot.

        :param key_ref: The key slot.
        """
        logger.debug(f"Getting public key for {key_ref.name}")
        resp = self.protocol.send_apdu(0, INS.GENERATE_ASYM, 0x81, 0x00, key_ref.crt)
        data = Tlv.parse_dict(Tlv.unpack(TAG_PUBLIC_KEY, resp))
        attributes = self.get_algorithm_attributes(key_ref)
        if isinstance(attributes, EcAttributes):
            return _parse_ec_key(attributes.oid, data)
        else:  # RSA
            return _parse_rsa_key(data)

    def generate_rsa_key(
        self, key_ref: KEY_REF, key_size: RSA_SIZE
    ) -> rsa.RSAPublicKey:
        """Generate an RSA key in the given slot.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param key_size: The size of the RSA key.
        """
        if (4, 2, 0) <= self.version < (4, 3, 5):
            raise NotSupportedError("RSA key generation not supported on this YubiKey")

        logger.debug(f"Generating RSA private key for {key_ref.name}")
        if (
            EXTENDED_CAPABILITY_FLAGS.ALGORITHM_ATTRIBUTES_CHANGEABLE
            in self.extended_capabilities.flags
        ):
            attributes = RsaAttributes.create(key_size)
            self.set_algorithm_attributes(key_ref, attributes)
        elif key_size != RSA_SIZE.RSA2048:
            raise NotSupportedError("Algorithm attributes not supported")

        resp = self.protocol.send_apdu(0, INS.GENERATE_ASYM, 0x80, 0x00, key_ref.crt)
        data = Tlv.parse_dict(Tlv.unpack(TAG_PUBLIC_KEY, resp))
        logger.info(f"RSA key generated for {key_ref.name}")
        return _parse_rsa_key(data)

    def generate_ec_key(self, key_ref: KEY_REF, curve_oid: CurveOid) -> EcPublicKey:
        """Generate an EC key in the given slot.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        :param curve_oid: The curve OID.
        """

        require_version(self.version, (5, 2, 0))

        if curve_oid not in OID:
            raise ValueError("Curve OID is not recognized")

        logger.debug(f"Generating EC private key for {key_ref.name}")
        attributes = EcAttributes.create(key_ref, curve_oid)
        self.set_algorithm_attributes(key_ref, attributes)

        resp = self.protocol.send_apdu(0, INS.GENERATE_ASYM, 0x80, 0x00, key_ref.crt)
        data = Tlv.parse_dict(Tlv.unpack(TAG_PUBLIC_KEY, resp))
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

        template = _get_key_template(private_key, key_ref, 0 < self.version[0] < 4)
        self.protocol.send_apdu(0, INS.PUT_DATA_ODD, 0x3F, 0xFF, bytes(template))
        logger.info(f"Private key imported for {key_ref.name}")

    def delete_key(self, key_ref: KEY_REF) -> None:
        """Delete the contents of a key slot.

        Requires Admin PIN verification.

        :param key_ref: The key slot.
        """
        if 0 < self.version[0] < 4:
            # Import over the key
            self.put_key(
                key_ref, rsa.generate_private_key(65537, 2048, default_backend())
            )
        else:
            # Delete key by changing the key attributes twice.
            self.put_data(  # Use put_data to avoid checking for RSA 4096 support
                key_ref.algorithm_attributes_do, RsaAttributes.create(RSA_SIZE.RSA4096)
            )
            self.set_algorithm_attributes(
                key_ref, RsaAttributes.create(RSA_SIZE.RSA2048)
            )

    def _select_certificate(self, key_ref: KEY_REF) -> None:
        logger.debug(f"Selecting certificate for key {key_ref.name}")
        try:
            require_version(self.version, (5, 2, 0))
            data: bytes = Tlv(0x60, Tlv(0x5C, int2bytes(DO.CARDHOLDER_CERTIFICATE)))
            if self.version <= (5, 4, 3):
                # These use a non-standard byte in the command.
                data = b"\x06" + data  # 6 is the length of the data.
            self.protocol.send_apdu(
                0,
                INS.SELECT_DATA,
                3 - key_ref,
                0x04,
                data,
            )
        except NotSupportedError:
            if key_ref == KEY_REF.AUT:
                return  # Older version still support AUT, which is the default slot.
            raise

    def get_certificate(self, key_ref: KEY_REF) -> x509.Certificate:
        """Get a certificate from a slot.

        :param key_ref: The slot.
        """
        logger.debug(f"Getting certificate for key {key_ref.name}")
        if key_ref == KEY_REF.ATT:
            require_version(self.version, (5, 2, 0))
            data = self.get_data(DO.ATT_CERTIFICATE)
        else:
            self._select_certificate(key_ref)
            data = self.get_data(DO.CARDHOLDER_CERTIFICATE)
        if not data:
            raise ValueError("No certificate found!")
        return x509.load_der_x509_certificate(data, default_backend())

    def put_certificate(self, key_ref: KEY_REF, certificate: x509.Certificate) -> None:
        """Import a certificate into a slot.

        Requires Admin PIN verification.

        :param key_ref: The slot.
        :param certificate: The X.509 certificate to import.
        """
        cert_data = certificate.public_bytes(Encoding.DER)
        logger.debug(f"Importing certificate for key {key_ref.name}")
        if key_ref == KEY_REF.ATT:
            require_version(self.version, (5, 2, 0))
            self.put_data(DO.ATT_CERTIFICATE, cert_data)
        else:
            self._select_certificate(key_ref)
            self.put_data(DO.CARDHOLDER_CERTIFICATE, cert_data)
        logger.info(f"Certificate imported for key {key_ref.name}")

    def delete_certificate(self, key_ref: KEY_REF) -> None:
        """Delete a certificate in a slot.

        Requires Admin PIN verification.

        :param key_ref: The slot.
        """
        logger.debug(f"Deleting certificate for key {key_ref.name}")
        if key_ref == KEY_REF.ATT:
            require_version(self.version, (5, 2, 0))
            self.put_data(DO.ATT_CERTIFICATE, b"")
        else:
            self._select_certificate(key_ref)
            self.put_data(DO.CARDHOLDER_CERTIFICATE, b"")
        logger.info(f"Certificate deleted for key {key_ref.name}")

    def attest_key(self, key_ref: KEY_REF) -> x509.Certificate:
        """Create an attestation certificate for a key.

        The certificate is written to the certificate slot for the key, and its
        content is returned.

        Requires User PIN verification.

        :param key_ref: The key slot.
        """
        require_version(self.version, (5, 2, 0))
        logger.debug(f"Attesting key {key_ref.name}")
        self.protocol.send_apdu(0x80, INS.GET_ATTESTATION, key_ref, 0)
        logger.info(f"Attestation certificate created for {key_ref.name}")
        return self.get_certificate(key_ref)

    def sign(self, message: bytes, hash_algorithm: hashes.HashAlgorithm) -> bytes:
        """Sign a message using the SIG key.

        Requires User PIN verification.

        :param message: The message to sign.
        :param hash_algorithm: The pre-signature hash algorithm.
        """
        attributes = self.get_algorithm_attributes(KEY_REF.SIG)
        padded = _pad_message(attributes, message, hash_algorithm)
        logger.debug(f"Signing a message with {attributes}")
        response = self.protocol.send_apdu(0, INS.PSO, 0x9E, 0x9A, padded)
        logger.info("Message signed")
        if attributes.algorithm_id == 0x13:
            ln = len(response) // 2
            return encode_dss_signature(
                int.from_bytes(response[:ln], "big"),
                int.from_bytes(response[ln:], "big"),
            )
        return response

    def decrypt(self, value: Union[bytes, EcPublicKey]) -> bytes:
        """Decrypt a value using the DEC key.

        For RSA the `value` should be an encrypted block.
        For ECDH the `value` should be a peer public-key to perform the key exchange
        with, and the result will be the derived shared secret.

        Requires (extended) User PIN verification.

        :param value: The value to decrypt.
        """
        attributes = self.get_algorithm_attributes(KEY_REF.DEC)
        logger.debug(f"Decrypting a value with {attributes}")

        if isinstance(value, ec.EllipticCurvePublicKey):
            data = value.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        elif isinstance(value, x25519.X25519PublicKey):
            data = value.public_bytes(Encoding.Raw, PublicFormat.Raw)
        elif isinstance(value, bytes):
            data = value

        if isinstance(attributes, RsaAttributes):
            data = b"\0" + data
        elif isinstance(attributes, EcAttributes):
            data = Tlv(0xA6, Tlv(0x7F49, Tlv(0x86, data)))

        response = self.protocol.send_apdu(0, INS.PSO, 0x80, 0x86, data)
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
        attributes = self.get_algorithm_attributes(KEY_REF.AUT)
        padded = _pad_message(attributes, message, hash_algorithm)
        logger.debug(f"Authenticating a message with {attributes}")
        response = self.protocol.send_apdu(
            0, INS.INTERNAL_AUTHENTICATE, 0x0, 0x0, padded
        )
        logger.info("Message authenticated")
        if attributes.algorithm_id == 0x13:
            ln = len(response) // 2
            return encode_dss_signature(
                int.from_bytes(response[:ln], "big"),
                int.from_bytes(response[ln:], "big"),
            )
        return response
