from .core import (
    Tlv,
    Version,
    NotSupportedError,
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
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec

import os
import abc
from enum import Enum, IntEnum, IntFlag, unique
from dataclasses import dataclass
from typing import Optional, Tuple, ClassVar, Mapping
import time
import struct
import logging

from typing import NamedTuple

logger = logging.getLogger(__name__)

DEFAULT_USER_PIN = "123456"
DEFAULT_ADMIN_PIN = "12345678"


class _KeySlot(NamedTuple):
    value: str
    indx: int
    key_id: int
    fingerprint: int
    gen_time: int
    uif: int  # touch policy
    crt: bytes  # Control Reference Template


@unique
class KEY_SLOT(_KeySlot, Enum):  # noqa: N801
    SIG = _KeySlot("SIGNATURE", 1, 0xC1, 0xC7, 0xCE, 0xD6, Tlv(0xB6))
    ENC = _KeySlot("ENCRYPTION", 2, 0xC2, 0xC8, 0xCF, 0xD7, Tlv(0xB8))
    AUT = _KeySlot("AUTHENTICATION", 3, 0xC3, 0xC9, 0xD0, 0xD8, Tlv(0xA4))
    ATT = _KeySlot(
        "ATTESTATION", 4, 0xDA, 0xDB, 0xDD, 0xD9, Tlv(0xB6, Tlv(0x84, b"\x81"))
    )


@unique
class TOUCH_MODE(IntEnum):  # noqa: N801
    OFF = 0x00
    ON = 0x01
    FIXED = 0x02
    CACHED = 0x03
    CACHED_FIXED = 0x04

    @property
    def is_fixed(self):
        return self in (TOUCH_MODE.FIXED, TOUCH_MODE.CACHED_FIXED)

    def __str__(self):
        if self == TOUCH_MODE.FIXED:
            return "On (fixed)"
        if self == TOUCH_MODE.CACHED_FIXED:
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
    ACTIVATE = 0x44
    GENERATE_ASYM = 0x47
    GET_CHALLENGE = 0x84
    SELECT_DATA = 0xA5
    SEND_REMAINING = 0xC0
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
TAG_ALGORITHM_ATTRIBUTES_SIG = 0xC1
TAG_ALGORITHM_ATTRIBUTES_DEC = 0xC2
TAG_ALGORITHM_ATTRIBUTES_AUT = 0xC3
TAG_ALGORITHM_ATTRIBUTES_ATT = 0xDA
TAG_FINGERPRINTS = 0xC5
TAG_CA_FINGERPRINTS = 0xC6
TAG_GENERATION_TIMES = 0xCD
TAG_SIGNATURE_COUNTER = 0x93


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
    KEY_INFORMATION = 0xDE
    SECURITY_SUPPORT_TEMPLATE = 0x7A
    CARDHOLDER_CERTIFICATE = 0x7F21
    KDF = 0xF9

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
        """OpenPGP version (tuple of 2 integers: main version, seconday version)."""
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
    user_pin_policy: PIN_POLICY
    user_max_len: int
    reset_max_len: int
    admin_max_len: int
    user_attempts: int
    reset_attempts: int
    admin_attempts: int

    def get_max_len(self, pw: PW) -> int:
        return getattr(self, f"{pw.name.lower()}_max_len")

    def get_attempts(self, pw: PW) -> int:
        return getattr(self, f"{pw.name.lower()}_attempts")

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


@dataclass
class DiscretionaryDataObjects:
    extended_capabilities: ExtendedCapabilities
    attributes_sig: bytes
    attributes_dec: bytes
    attributes_aut: bytes
    attributes_att: bytes
    pw_status: PwStatus
    fingerprints: bytes
    ca_fingerprints: bytes
    generation_times: bytes
    key_information: bytes
    uif_sig: Optional[bytes]
    uif_dec: Optional[bytes]
    uif_aut: Optional[bytes]
    uif_att: Optional[bytes]

    @classmethod
    def parse(cls, encoded: bytes) -> "DiscretionaryDataObjects":
        data = Tlv.parse_dict(encoded)
        return cls(
            ExtendedCapabilities.parse(data[TAG_EXTENDED_CAPABILITIES]),
            data[TAG_ALGORITHM_ATTRIBUTES_SIG],
            data[TAG_ALGORITHM_ATTRIBUTES_DEC],
            data[TAG_ALGORITHM_ATTRIBUTES_AUT],
            data[TAG_ALGORITHM_ATTRIBUTES_ATT],
            PwStatus.parse(data[DO.PW_STATUS_BYTES]),
            data[TAG_FINGERPRINTS],
            data[TAG_CA_FINGERPRINTS],
            data[TAG_GENERATION_TIMES],
            data[DO.KEY_INFORMATION],
            data[DO.UIF_SIG],
            data[DO.UIF_DEC],
            data[DO.UIF_AUT],
            data[DO.UIF_ATT],
        )


@dataclass
class ApplicationRelatedData:
    aid: OpenPgpAid
    historical: bytes
    extended_length_info: Optional[ExtendedLengthInfo]
    general_feature_management: Optional[GENERAL_FEATURE_MANAGEMENT]
    discretionary: DiscretionaryDataObjects

    @classmethod
    def parse(cls, encoded: bytes) -> "ApplicationRelatedData":
        data = Tlv.parse_dict(Tlv.unpack(DO.APPLICATION_RELATED_DATA, encoded))
        return cls(
            OpenPgpAid(data[DO.AID]),
            data[DO.HISTORICAL_BYTES],
            ExtendedLengthInfo.parse(data[DO.EXTENDED_LENGTH_INFO])
            if DO.EXTENDED_LENGTH_INFO in data
            else None,
            GENERAL_FEATURE_MANAGEMENT(
                Tlv.unpack(0x81, data[DO.GENERAL_FEATURE_MANAGEMENT])[0]
            )
            if DO.GENERAL_FEATURE_MANAGEMENT in data
            else None,
            DiscretionaryDataObjects.parse(data[TAG_DISCRETIONARY]),
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
    def process(self, pin: str, pw: PW) -> bytes:
        """Runs the KDF on the input PIN."""

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
    def get_bytes(self) -> bytes:
        raise NotImplementedError()


@dataclass
class KdfNone(Kdf):
    algorithm = 0

    @classmethod
    def _parse_data(cls, data) -> "KdfNone":
        return cls()

    def process(self, pw, pin):
        return pin.encode()

    def get_bytes(self):
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
    user_salt: bytes
    reset_salt: bytes
    admin_salt: bytes
    user_initial_hash: Optional[bytes]
    admin_initial_hash: Optional[bytes]

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
        user_salt = os.urandom(8)
        admin_salt = os.urandom(8)
        return cls(
            hash_algorithm,
            iteration_count,
            user_salt,
            os.urandom(8),
            admin_salt,
            cls._do_process(
                hash_algorithm, iteration_count, user_salt + DEFAULT_USER_PIN.encode()
            ),
            cls._do_process(
                hash_algorithm, iteration_count, admin_salt + DEFAULT_ADMIN_PIN.encode()
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
        return getattr(self, f"{pw.name.lower()}_salt")

    def process(self, pw, pin):
        salt = self.get_salt(pw) or self.user_salt
        data = salt + pin.encode()
        return self._do_process(self.hash_algorithm, self.iteration_count, data)

    def get_bytes(self):
        return (
            Tlv(0x81, struct.pack(">B", self.algorithm))
            + Tlv(0x82, struct.pack(">B", self.hash_algorithm))
            + Tlv(0x83, struct.pack(">I", self.iteration_count))
            + Tlv(0x84, self.user_salt)
            + (Tlv(0x85, self.reset_salt) if self.reset_salt else b"")
            + (Tlv(0x86, self.admin_salt) if self.admin_salt else b"")
            + (Tlv(0x87, self.user_initial_hash) if self.user_initial_hash else b"")
            + (Tlv(0x88, self.admin_initial_hash) if self.admin_initial_hash else b"")
        )


@unique
class OID(bytes, Enum):
    SECP256R1 = b"\x2a\x86\x48\xce\x3d\x03\x01\x07"
    SECP256K1 = b"\x2b\x81\x04\x00\x0a"
    SECP384R1 = b"\x2b\x81\x04\x00\x22"
    SECP521R1 = b"\x2b\x81\x04\x00\x23"
    BRAINPOOLP256R1 = b"\x2b\x24\x03\x03\x02\x08\x01\x01\x07"
    BRAINPOOLP384R1 = b"\x2b\x24\x03\x03\x02\x08\x01\x01\x0b"
    BRAINPOOLP512R1 = b"\x2b\x24\x03\x03\x02\x08\x01\x01\x0d"
    X25519 = b"\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01"
    ED25519 = b"\x2b\x06\x01\x04\x01\xda\x47\x0f\x01"

    @classmethod
    def for_name(cls, name):
        try:
            return getattr(cls, name.upper())
        except AttributeError:
            raise ValueError("Unsupported curve: " + name)


def _get_curve_name(key):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.curve.name
    cls_name = key.__class__.__name__
    if "Ed25519" in cls_name:
        return "ed25519"
    if "X25519" in cls_name:
        return "x25519"
    raise ValueError("Unsupported private key")


def _format_rsa_attributes(key_size):
    return struct.pack(">BHHB", 0x01, key_size, 32, 0)


def _format_ec_attributes(key_slot, curve_name):
    if curve_name in ("ed25519", "x25519"):
        algorithm = b"\x16"
    elif key_slot == KEY_SLOT.ENC:
        algorithm = b"\x12"
    else:
        algorithm = b"\x13"
    return algorithm + OID.for_name(curve_name)


def _get_key_attributes(key, key_slot):
    if isinstance(key, rsa.RSAPrivateKeyWithSerialization):
        if key.private_numbers().public_numbers.e != 65537:
            raise ValueError("RSA keys with e != 65537 are not supported!")
        return _format_rsa_attributes(key.key_size)
    curve_name = _get_curve_name(key)
    return _format_ec_attributes(key_slot, curve_name)


def _get_key_template(key, key_slot, crt=False):
    def _pack_tlvs(tlvs):
        header = b""
        body = b""
        for tlv in tlvs:
            header += tlv[: -tlv.length]
            body += tlv.value
        return Tlv(0x7F48, header) + Tlv(0x5F48, body)

    values: Tuple[Tlv, ...]

    if isinstance(key, rsa.RSAPrivateKeyWithSerialization):
        rsa_numbers = key.private_numbers()
        ln = (key.key_size // 8) // 2

        e = Tlv(0x91, b"\x01\x00\x01")  # e=65537
        p = Tlv(0x92, int2bytes(rsa_numbers.p, ln))
        q = Tlv(0x93, int2bytes(rsa_numbers.q, ln))
        values = (e, p, q)
        if crt:
            dp = Tlv(0x94, int2bytes(rsa_numbers.dmp1, ln))
            dq = Tlv(0x95, int2bytes(rsa_numbers.dmq1, ln))
            qinv = Tlv(0x96, int2bytes(rsa_numbers.iqmp, ln))
            n = Tlv(0x97, int2bytes(rsa_numbers.public_numbers.n, 2 * ln))
            values += (dp, dq, qinv, n)

    elif isinstance(key, ec.EllipticCurvePrivateKeyWithSerialization):
        ec_numbers = key.private_numbers()
        ln = key.key_size // 8

        privkey = Tlv(0x92, int2bytes(ec_numbers.private_value, ln))
        values = (privkey,)

    elif _get_curve_name(key) in ("ed25519", "x25519"):
        privkey = Tlv(
            0x92, key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        values = (privkey,)

    return Tlv(0x4D, key_slot.crt + _pack_tlvs(values))


class OpenPgpSession:
    def __init__(self, connection: SmartCardConnection):
        self.protocol = SmartCardProtocol(connection)
        try:
            self.protocol.select(AID.OPENPGP)
        except ApduError as e:
            if e.sw in (SW.NO_INPUT_DATA, SW.CONDITIONS_NOT_SATISFIED):
                # Not activated
                self.protocol.send_apdu(0, INS.ACTIVATE, 0, 0)
                self.protocol.select(AID.OPENPGP)
            else:
                raise
        self._version = self._read_version()
        if self.version >= (4, 0, 0):
            self.protocol.apdu_format = ApduFormat.EXTENDED
        self._app_data = self.get_application_related_data()

    @property
    def version(self) -> Version:
        return self._version

    def get_challenge(self, length: int) -> bytes:
        """Get random data from the YubiKey."""
        e = self._app_data.discretionary.extended_capabilities
        if EXTENDED_CAPABILITY_FLAGS.GET_CHALLENGE not in e.flags:
            raise NotSupportedError("GET_CHALLENGE is not supported")
        if not 0 < length <= e.challenge_max_length:
            raise NotSupportedError("Unsupported challenge length")
        return self.protocol.send_apdu(0, INS.GET_CHALLENGE, 0, 0, le=length)

    def get_data(self, do: DO) -> bytes:
        return self.protocol.send_apdu(0, INS.GET_DATA, do >> 8, do & 0xFF)

    def put_data(self, do: DO, data: bytes) -> None:
        self.protocol.send_apdu(0, INS.PUT_DATA, do >> 8, do & 0xFF, data)

    def get_pin_status(self) -> PwStatus:
        return PwStatus.parse(self.get_data(DO.PW_STATUS_BYTES))

    def get_signature_counter(self) -> int:
        s = SecuritySupportTemplate.parse(self.get_data(DO.SECURITY_SUPPORT_TEMPLATE))
        return s.signature_counter

    def _select_certificate(self, key_slot):
        try:
            require_version(self.version, (5, 2, 0))
            data: bytes = Tlv(0x60, Tlv(0x5C, b"\x7f\x21"))
            if self.version <= (5, 4, 3):
                # These use a non-standard byte in the command.
                data = b"\x06" + data  # 6 is the length of the data.
            self.protocol.send_apdu(
                0,
                INS.SELECT_DATA,
                3 - key_slot.indx,
                0x04,
                data,
            )
        except NotSupportedError:
            if key_slot == KEY_SLOT.AUT:
                return  # Older version still support AUT, which is the default slot.
            raise

    def _read_version(self):
        bcd = self.protocol.send_apdu(0, INS.GET_VERSION, 0, 0)
        return Version(*(_bcd(x) for x in bcd))

    def get_application_related_data(self):
        """Read the Application Related Data."""
        return ApplicationRelatedData.parse(self.get_data(DO.APPLICATION_RELATED_DATA))

    def set_signature_pin_policy(self, pin_policy: PIN_POLICY) -> None:
        """Requires Admin PIN verification."""
        data = struct.pack(">B", pin_policy)
        self.put_data(DO.PW_STATUS_BYTES, data)

    def _block_pins(self):
        status = self.get_pin_status()
        for _ in range(status.user_attempts):
            try:
                self.protocol.send_apdu(0, INS.VERIFY, 0, PW.USER, _INVALID_PIN)
            except ApduError:
                pass
        for _ in range(status.admin_attempts):
            try:
                self.protocol.send_apdu(0, INS.VERIFY, 0, PW.ADMIN, _INVALID_PIN)
            except ApduError:
                pass

    def reset(self) -> None:
        """Performs a factory reset on the OpenPGP application.

        WARNING: This will delete all stored keys, certificates and other data.
        """
        require_version(self.version, (1, 0, 6))
        self._block_pins()
        self.protocol.send_apdu(0, INS.TERMINATE, 0, 0)
        self.protocol.send_apdu(0, INS.ACTIVATE, 0, 0)

    def get_kdf(self):
        """Get the Key Derivation Function data object."""
        try:
            data = self.get_data(DO.KDF)
        except ApduError:
            data = b""
        return Kdf.parse(data)

    def set_kdf(self, kdf: Kdf) -> None:
        """Set up a PIN Key Derivation Function.

        This enables (or disables) the use of a KDF for PIN verification, as well
        as resetting the User and Admin PINs to their default (initial) values.

        If a Reset Code is present, it will be invalidated.

        This command requires Admin PIN verification.
        """

        self.put_data(DO.KDF, kdf.get_bytes())

    def _verify(self, pw, pin):
        try:
            pin_enc = self.get_kdf().process(pw, pin)
            self.protocol.send_apdu(0, INS.VERIFY, 0, pw, pin_enc)
        except ApduError:
            attempts = self.get_pin_status().get_attempts(pw)
            raise ValueError(f"Invalid PIN, {attempts} tries remaining.")

    def verify_pin(self, pin):
        """Verify the User PIN.

        This will unlock functionality that requires User PIN verification.
        """
        self._verify(PW.USER, pin)

    def verify_admin(self, admin_pin):
        """Verify the Admin PIN.

        This will unlock functionality that requires Admin PIN verification.
        """
        self._verify(PW.ADMIN, admin_pin)

    def _change(self, pw, pin, new_pin):
        try:
            pin = self.get_kdf().process(pw, pin)
            new_pin = self.get_kdf().process(pw, new_pin)
            self.protocol.send_apdu(0, INS.CHANGE_PIN, 0, pw, pin + new_pin)
        except ApduError as e:
            if e.sw == SW.CONDITIONS_NOT_SATISFIED:
                raise ValueError("Conditions of use not satisfied.")
            else:
                remaining = self.get_pin_status().get_attempts(pw)
                raise ValueError(f"Invalid PIN, {remaining} tries remaining.")

    def change_pin(self, pin: str, new_pin: str) -> None:
        """Change the User PIN."""
        self._change(PW.USER, pin, new_pin)

    def change_admin(self, admin_pin: str, new_admin_pin: str) -> None:
        """Change the Admin PIN."""
        self._change(PW.ADMIN, admin_pin, new_admin_pin)

    def set_reset_code(self, reset_code: str) -> None:
        """Set the Reset Code for User PIN.

        The Reset Code can be used to set a new User PIN if it is lost or becomes
        blocked, using the reset_pin method.

        This command requires Admin PIN verification.
        """
        data = self.get_kdf().process(PW.RESET, reset_code)
        self.put_data(DO.RESETTING_CODE, data)

    def reset_pin(self, new_pin: str, reset_code: Optional[str] = None) -> None:
        """Resets the User PIN to a new value.

        This command requires Admin PIN verification, or the Reset Code.
        """
        p1 = 2
        kdf = self.get_kdf()
        data = kdf.process(PW.USER, new_pin)
        if reset_code:
            data = kdf.process(PW.RESET, reset_code) + data
            p1 = 0

        try:
            self.protocol.send_apdu(0, INS.RESET_RETRY_COUNTER, p1, PW.USER, data)
        except ApduError as e:
            if e.sw == SW.CONDITIONS_NOT_SATISFIED:
                raise ValueError("Conditions of use not satisfied.")
            else:
                reset_remaining = self.get_pin_status().reset_attempts
                raise ValueError(
                    f"Invalid Reset Code, {reset_remaining} tries remaining."
                )

    @property
    def supported_touch_policies(self):
        if self.version < (4, 2, 0):
            return []
        if self.version < (5, 2, 1):
            return [TOUCH_MODE.ON, TOUCH_MODE.OFF, TOUCH_MODE.FIXED]
        if self.version >= (5, 2, 1):
            return [
                TOUCH_MODE.ON,
                TOUCH_MODE.OFF,
                TOUCH_MODE.FIXED,
                TOUCH_MODE.CACHED,
                TOUCH_MODE.CACHED_FIXED,
            ]

    @property
    def supports_attestation(self):
        return self.version >= (5, 2, 1)

    def get_touch(self, key_slot):
        if not self.supported_touch_policies:
            raise ValueError("Touch policy is available on YubiKey 4 or later.")
        if key_slot == KEY_SLOT.ATT and not self.supports_attestation:
            raise ValueError("Attestation key not available on this device.")
        data = self.get_data(key_slot.uif)
        return TOUCH_MODE(data[0])

    def set_touch(self, key_slot, mode):
        """Requires Admin PIN verification."""
        if not self.supported_touch_policies:
            raise ValueError("Touch policy is available on YubiKey 4 or later.")
        if mode not in self.supported_touch_policies:
            raise ValueError("Touch policy not available on this device.")
        self.put_data(
            key_slot.uif, struct.pack(">BB", mode, GENERAL_FEATURE_MANAGEMENT.BUTTON)
        )

    def set_pin_attempts(self, user_tries, reset_tries, admin_tries):
        """Requires Admin PIN verification."""
        if self.version[0] == 1:
            # YubiKey NEO
            require_version(self.version, (1, 0, 7))
        else:
            require_version(self.version, (4, 3, 1))

        self.protocol.send_apdu(
            0,
            INS.SET_PIN_RETRIES,
            0,
            0,
            struct.pack(">BBB", user_tries, reset_tries, admin_tries),
        )

    def read_certificate(self, key_slot):
        if key_slot == KEY_SLOT.ATT:
            require_version(self.version, (5, 2, 0))
            data = self.get_data(DO.ATT_CERTIFICATE)
        else:
            self._select_certificate(key_slot)
            data = self.get_data(DO.CARDHOLDER_CERTIFICATE)
        if not data:
            raise ValueError("No certificate found!")
        return x509.load_der_x509_certificate(data, default_backend())

    def import_certificate(self, key_slot, certificate):
        """Requires Admin PIN verification."""
        cert_data = certificate.public_bytes(Encoding.DER)
        if key_slot == KEY_SLOT.ATT:
            require_version(self.version, (5, 2, 0))
            self.put_data(DO.ATT_CERTIFICATE, cert_data)
        else:
            self._select_certificate(key_slot)
            self.put_data(DO.CARDHOLDER_CERTIFICATE, cert_data)

    def import_key(self, key_slot, key, fingerprint=None, timestamp=None):
        """Requires Admin PIN verification."""
        if self.version >= (4, 0, 0):
            attributes = _get_key_attributes(key, key_slot)
            self.put_data(key_slot.key_id, attributes)

        template = _get_key_template(key, key_slot, self.version < (4, 0, 0))
        self.protocol.send_apdu(0, INS.PUT_DATA_ODD, 0x3F, 0xFF, template)

        if fingerprint is not None:
            self.put_data(key_slot.fingerprint, fingerprint)

        if timestamp is not None:
            self.put_data(key_slot.gen_time, struct.pack(">I", timestamp))

    def generate_rsa_key(self, key_slot, key_size, timestamp=None):
        """Requires Admin PIN verification."""
        if (4, 2, 0) <= self.version < (4, 3, 5):
            raise NotSupportedError("RSA key generation not supported on this YubiKey")

        if timestamp is None:
            timestamp = int(time.time())

        neo = self.version < (4, 0, 0)
        if not neo:
            attributes = _format_rsa_attributes(key_size)
            self.put_data(key_slot.key_id, attributes)
        elif key_size != 2048:
            raise ValueError("Unsupported key size!")
        resp = self.protocol.send_apdu(0, INS.GENERATE_ASYM, 0x80, 0x00, key_slot.crt)

        data = Tlv.parse_dict(Tlv.unpack(0x7F49, resp))
        numbers = rsa.RSAPublicNumbers(bytes2int(data[0x82]), bytes2int(data[0x81]))

        self.put_data(key_slot.gen_time, struct.pack(">I", timestamp))
        # TODO: Calculate and write fingerprint

        return numbers.public_key(default_backend())

    def generate_ec_key(self, key_slot, curve_name, timestamp=None):
        """Requires Admin PIN verification."""
        require_version(self.version, (5, 2, 0))
        if timestamp is None:
            timestamp = int(time.time())

        attributes = _format_ec_attributes(key_slot, curve_name)
        self.put_data(key_slot.key_id, attributes)
        resp = self.protocol.send_apdu(0, INS.GENERATE_ASYM, 0x80, 0x00, key_slot.crt)

        data = Tlv.parse_dict(Tlv.unpack(0x7F49, resp))
        pubkey_enc = data[0x86]

        self.put_data(key_slot.gen_time, struct.pack(">I", timestamp))
        # TODO: Calculate and write fingerprint

        if curve_name == "x25519":
            # Added in 2.0
            from cryptography.hazmat.primitives.asymmetric import x25519

            return x25519.X25519PublicKey.from_public_bytes(pubkey_enc)
        if curve_name == "ed25519":
            # Added in 2.6
            from cryptography.hazmat.primitives.asymmetric import ed25519

            return ed25519.Ed25519PublicKey.from_public_bytes(pubkey_enc)

        curve = getattr(ec, curve_name.upper())
        try:
            # Added in cryptography 2.5
            return ec.EllipticCurvePublicKey.from_encoded_point(curve(), pubkey_enc)
        except AttributeError:
            return ec.EllipticCurvePublicNumbers.from_encoded_point(
                curve(), pubkey_enc
            ).public_key(default_backend())

    def delete_key(self, key_slot):
        """Requires Admin PIN verification."""
        if self.version < (4, 0, 0):
            # Import over the key
            self.import_key(
                key_slot,
                rsa.generate_private_key(65537, 2048, default_backend()),
                b"\0" * 20,
                0,
            )
        else:
            # Delete key by changing the key attributes twice.
            self.put_data(key_slot.key_id, _format_rsa_attributes(4096))
            self.put_data(key_slot.key_id, _format_rsa_attributes(2048))

    def delete_certificate(self, key_slot):
        """Requires Admin PIN verification."""
        if key_slot == KEY_SLOT.ATT:
            require_version(self.version, (5, 2, 0))
            self.put_data(DO.ATT_CERTIFICATE, b"")
        else:
            self._select_certificate(key_slot)
            self.put_data(DO.CARDHOLDER_CERTIFICATE, b"")

    def attest(self, key_slot):
        """Requires User PIN verification."""
        require_version(self.version, (5, 2, 0))
        self.protocol.send_apdu(0x80, INS.GET_ATTESTATION, key_slot.indx, 0)
        return self.read_certificate(key_slot)
