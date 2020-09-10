from __future__ import absolute_import

from .core import (
    Tlv,
    AID,
    CommandError,
    NotSupportedError,
    BadResponseError,
)
from .core.iso7816 import Iso7816Application, ApduError, SW

from cryptography import x509
from cryptography.utils import int_to_bytes, int_from_bytes
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

from collections import namedtuple
from enum import Enum, IntEnum, unique, auto

import logging
import six
import os
import re


logger = logging.getLogger(__name__)


class ALGORITHM(Enum):
    EC = auto()
    RSA = auto()


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
        return int(re.search(r"\d+$", self.name).group())

    @classmethod
    def from_public_key(cls, key):
        if isinstance(key, asymmetric.rsa.RSAPublicKey):
            return getattr(cls, "RSA%d" % key.key_size)
        elif isinstance(key, asymmetric.ec.EllipticCurvePublicKey):
            curve_name = key.curve.name
            if curve_name == "secp256r1":
                return cls.ECCP256
            elif curve_name == "secp384r1":
                return cls.ECCP384
        raise ValueError("Unsupported key type: %s" % type(key), key=key)


@unique
class SLOT(IntEnum):
    AUTHENTICATION = 0x9A
    CARD_MANAGEMENT = 0x9B
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
CHALLENGE_LEN = 8

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

TDES = 0x03


class InvalidPinError(CommandError):
    def __init__(self, attempts_remaining):
        super(InvalidPinError, self).__init__(
            "Invalid PIN/PUK. Remaining attempts: %d" % attempts_remaining
        )
        self.attempts_remaining = attempts_remaining


def _pin_bytes(pin):
    pin = pin.encode("utf-8")
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


class PinMetadata(
    namedtuple(
        "PinMetadata", ["default_value", "total_attempts", "attempts_remaining"],
    )
):
    __slots__ = ()


class ManagementKeyMetadata(
    namedtuple("ManagementKeyMetadata", ["default_value", "touch_policy"])
):
    __slots__ = ()


class SlotMetadata(
    namedtuple(
        "SlotMetadata",
        ["key_type", "pin_policy", "touch_policy", "generated", "public_key_encoded"],
    )
):
    __slots__ = ()

    @property
    def public_key(self):
        return _parse_device_public_key(self.public_key_encoded)


def _pad_message(key_type, message, hash_algorithm, padding):
    if key_type.algorithm == ALGORITHM.EC:
        h = hashes.Hash(hash_algorithm)
        h.update(message)
        hashed = h.finalize()
        byte_len = key_type.bit_len // 8
        if len(hashed) < byte_len:
            return hashed.rjust(byte_len // 8, b"\0")
        return hashed[:byte_len]
    elif key_type.algorithm == ALGORITHM.RSA:
        # Sign with a dummy key, then encrypt the signature to get the padded message
        e = 65537
        dummy = asymmetric.rsa.generate_private_key(
            e, key_type.bit_len, default_backend()
        )
        signature = dummy.sign(message, padding, hash_algorithm)
        # Raw (textbook) RSA encrypt
        n = dummy.public_key().public_numbers().n
        return int_to_bytes(
            pow(int_from_bytes(signature, "big"), e, n), key_type.bit_len // 8
        )


def _unpad_message(padded, padding):
    e = 65537
    dummy = asymmetric.rsa.generate_private_key(e, len(padded) * 8, default_backend())
    # Raw (textbook) RSA encrypt
    n = dummy.public_key().public_numbers().n
    encrypted = int_to_bytes(pow(int_from_bytes(padded, "big"), e, n), len(padded))
    return dummy.decrypt(encrypted, padding)


def _check_key_support(version, key_type, pin_policy, touch_policy):
    if version < (4, 0, 0):
        if key_type == KEY_TYPE.ECCP384:
            raise NotSupportedError("ECCP384 requires YubiKey 4 or later")
        if touch_policy != TOUCH_POLICY.DEFAULT or pin_policy != PIN_POLICY.DEFAULT:
            raise NotSupportedError("PIN/Touch policy requires YubiKey 4 or later")
    if touch_policy == TOUCH_POLICY.CACHED and version < (4, 3, 0):
        raise NotSupportedError("Cached touch policy requires YubiKey 4 or later")


def _parse_device_public_key(key_type, encoded):
    data = Tlv.parse_dict(encoded)
    if key_type.algorithm == ALGORITHM.RSA:
        modulus = int_from_bytes(data[0x81], "big")
        exponent = int_from_bytes(data[0x82], "big")
        return asymmetric.rsa.RSAPublicNumbers(exponent, modulus).public_key(
            default_backend()
        )
    else:
        if key_type == KEY_TYPE.ECCP256:
            curve = asymmetric.ec.SECP256R1
        else:
            curve = asymmetric.ec.SECP384R1

        try:
            # Added in cryptography 2.5
            return asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                curve(), data[0x86]
            )
        except AttributeError:
            return asymmetric.ec.EllipticCurvePublicNumbers.from_encoded_point(
                curve(), data[0x86]
            ).public_key(default_backend())


class PivApplication(Iso7816Application):
    def __init__(self, connection):
        super(PivApplication, self).__init__(AID.PIV, connection)
        self.select()
        self._version = tuple(self.send_apdu(0, INS_GET_VERSION, 0, 0))
        self.enable_touch_workaround(self.version)
        self._current_pin_retries = 3
        self._max_pin_retries = 3

    @property
    def version(self):
        return self._version

    def reset(self):
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
        self.send_apdu(0, INS_RESET, 0, 0)
        self._current_pin_retries = 3
        self._max_pin_retries = 3

    def authenticate(self, management_key):
        response = self.send_apdu(
            0,
            INS_AUTHENTICATE,
            TDES,
            SLOT.CARD_MANAGEMENT,
            Tlv(TAG_DYN_AUTH, Tlv(TAG_AUTH_WITNESS)),
        )
        witness = Tlv.unwrap(TAG_AUTH_WITNESS, Tlv.unwrap(TAG_DYN_AUTH, response))
        challenge = os.urandom(8)

        backend = default_backend()
        cipher_key = algorithms.TripleDES(management_key)
        cipher = Cipher(cipher_key, modes.ECB(), backend)  # nosec
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(witness) + decryptor.finalize()

        response = self.send_apdu(
            0,
            INS_AUTHENTICATE,
            TDES,
            SLOT.CARD_MANAGEMENT,
            Tlv(
                TAG_DYN_AUTH,
                Tlv(TAG_AUTH_WITNESS, decrypted) + Tlv(TAG_AUTH_CHALLENGE, challenge),
            ),
        )
        encrypted = Tlv.unwrap(TAG_AUTH_RESPONSE, Tlv.unwrap(TAG_DYN_AUTH, response))
        encryptor = cipher.encryptor()
        expected = encryptor.update(challenge) + encryptor.finalize()
        if not bytes_eq(expected, encrypted):
            raise BadResponseError("Device response is incorrect")

    def set_management_key(self, management_key):
        if len(management_key) != 24:
            raise ValueError("Management key must be 24 bytes")
        self.send_apdu(
            0,
            INS_SET_MGMKEY,
            0xFF,
            0xFF,  # 0xFE for touch, expose this?
            six.int2byte(TDES) + Tlv(SLOT.CARD_MANAGEMENT, management_key),
        )

    def verify_pin(self, pin):
        try:
            self.send_apdu(0, INS_VERIFY, 0, PIN_P2, _pin_bytes(pin))
            self._current_pin_retries = self._max_pin_retries
        except ApduError as e:
            retries = _retries_from_sw(self.version, e.sw)
            if retries is None:
                raise
            self._current_pin_retries = retries
            raise InvalidPinError(retries)

    def get_pin_attempts(self):
        if self.version >= (5, 3, 0):
            return self.get_pin_metadata().attempts_remaining
        try:
            self.send_apdu(0, INS_VERIFY, 0, PIN_P2)
            # Already verified, no way to know true count
            return self._current_pin_retries
        except ApduError as e:
            retries = _retries_from_sw(self.version, e.sw)
            if retries is None:
                raise
            self._current_pin_retries = retries
            return retries

    def change_pin(self, old_pin, new_pin):
        self._change_reference(INS_CHANGE_REFERENCE, PIN_P2, old_pin, new_pin)

    def change_puk(self, old_puk, new_puk):
        self._change_reference(INS_CHANGE_REFERENCE, PUK_P2, old_puk, new_puk)

    def unblock_pin(self, puk, new_pin):
        self._change_reference(INS_RESET_RETRY, PIN_P2, puk, new_pin)

    def set_pin_attempts(self, pin_attempts, puk_attempts):
        self.send_apdu(0, INS_SET_PIN_RETRIES, pin_attempts, puk_attempts)
        self._max_pin_retries = pin_attempts
        self._current_pin_retries = pin_attempts

    def get_pin_metadata(self):
        return self._get_pin_puk_metadata(PIN_P2)

    def get_puk_metadata(self):
        return self._get_pin_puk_metadata(PUK_P2)

    def get_management_key_metadata(self):
        if self.version < (5, 3, 0):
            raise NotSupportedError(
                "Management key metadata requires version 5.3.0 or later."
            )
        data = Tlv.parse_dict(
            self.send_apdu(0, INS_GET_METADATA, 0, SLOT.CARD_MANAGEMENT)
        )
        policy = data[TAG_METADATA_POLICY]
        return ManagementKeyMetadata(
            data[TAG_METADATA_IS_DEFAULT] != b"\0",
            TOUCH_POLICY(six.indexbytes(policy, INDEX_TOUCH_POLICY)),
        )

    def get_slot_metadata(self, slot):
        if self.version < (5, 3, 0):
            raise NotSupportedError("Slot metadata requires version 5.3.0 or later.")
        elif slot == SLOT.CARD_MANAGEMENT:
            raise ValueError(
                "This method cannot be used for the card management key, use "
                "get_management_key_metadata() instead"
            )
        data = Tlv.parse_dict(self.send_apdu(0, INS_GET_METADATA, 0, slot))
        policy = data[TAG_METADATA_POLICY]
        return SlotMetadata(
            KEY_TYPE(six.indexbytes(data[TAG_METADATA_ALGO], 0)),
            PIN_POLICY(six.indexbytes(policy, INDEX_PIN_POLICY)),
            TOUCH_POLICY(six.indexbytes(policy, INDEX_TOUCH_POLICY)),
            six.indexbytes(data[TAG_METADATA_ORIGIN], 0) == ORIGIN_GENERATED,
            data[TAG_METADATA_PUBLIC_KEY],
        )

    def sign(self, slot, key_type, message, hash_algorithm, padding=None):
        key_type = KEY_TYPE(key_type)
        padded = _pad_message(key_type, message, hash_algorithm, padding)
        return self._use_private_key(slot, key_type, padded, False)

    def decrypt(self, slot, cipher_text, padding):
        if len(cipher_text) == 1024 // 8:
            key_type = KEY_TYPE.RSA1024
        elif len(cipher_text) == 2048 // 8:
            key_type = KEY_TYPE.RSA2048
        else:
            raise ValueError("Invalid length of ciphertext")
        padded = self._use_private_key(slot, key_type, cipher_text, False)
        return _unpad_message(padded, padding)

    def calculate_secret(self, slot, peer_public_key):
        key_type = KEY_TYPE.from_public_key(peer_public_key)
        if key_type.algorithm != ALGORITHM.EC:
            raise ValueError("Unsupported key type")
        data = peer_public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return self._use_private_key(slot, key_type, data, True)

    def get_object(self, object_id):
        if object_id == OBJECT_ID.DISCOVERY:
            expected = OBJECT_ID.DISCOVERY
        else:
            expected = TAG_OBJ_DATA
        return Tlv.unwrap(
            expected,
            self.send_apdu(
                0, INS_GET_DATA, 0x3F, 0xFF, Tlv(TAG_OBJ_ID, int_to_bytes(object_id))
            ),
        )

    def put_object(self, object_id, data=None):
        self.send_apdu(
            0,
            INS_PUT_DATA,
            0x3F,
            0xFF,
            Tlv(TAG_OBJ_ID, int_to_bytes(object_id)) + Tlv(TAG_OBJ_DATA, data or b""),
        )

    def get_certificate(self, slot):
        data = Tlv.parse_dict(self.get_object(OBJECT_ID.from_slot(slot)))
        cert_info = data.get(TAG_CERT_INFO)
        if cert_info and six.indexbytes(cert_info, 0) != 0:
            raise NotSupportedError("Compressed certificates are not supported")
        try:
            return x509.load_der_x509_certificate(
                data.get(TAG_CERTIFICATE), default_backend()
            )
        except Exception as e:
            raise BadResponseError("Invalid certificate", e)

    def put_certificate(self, slot, certificate):
        cert_data = certificate.public_bytes(Encoding.DER)
        data = (
            Tlv(TAG_CERTIFICATE, cert_data) + Tlv(TAG_CERT_INFO, b"\0") + Tlv(TAG_LRC)
        )
        self.put_object(OBJECT_ID.from_slot(slot), data)

    def delete_certificate(self, slot):
        self.put_object(OBJECT_ID.from_slot(slot))

    def put_key(
        self,
        slot,
        private_key,
        pin_policy=PIN_POLICY.DEFAULT,
        touch_policy=TOUCH_POLICY.DEFAULT,
    ):
        key_type = KEY_TYPE.from_public_key(private_key.public_key())
        _check_key_support(self.version, key_type, pin_policy, touch_policy)
        ln = key_type.bit_len // 8
        numbers = private_key.private_numbers()
        if key_type.algorithm == ALGORITHM.RSA:
            if numbers.public_numbers.e != 65537:
                raise ValueError("RSA exponent must be 65537")
            ln //= 2
            data = (
                Tlv(0x01, int_to_bytes(numbers.p, ln))
                + Tlv(0x02, int_to_bytes(numbers.q, ln))
                + Tlv(0x03, int_to_bytes(numbers.dmp1, ln))
                + Tlv(0x04, int_to_bytes(numbers.dmq1, ln))
                + Tlv(0x05, int_to_bytes(numbers.iqmp, ln))
            )
        else:
            data = Tlv(0x06, int_to_bytes(numbers.private_value, ln))
        if pin_policy:
            data += Tlv(TAG_PIN_POLICY, six.int2byte(pin_policy))
        if touch_policy:
            data += Tlv(TAG_TOUCH_POLICY, six.int2byte(touch_policy))
        self.send_apdu(0, INS_IMPORT_KEY, key_type, slot, data)
        return key_type

    def generate_key(
        self,
        slot,
        key_type,
        pin_policy=PIN_POLICY.DEFAULT,
        touch_policy=TOUCH_POLICY.DEFAULT,
    ):
        key_type = KEY_TYPE(key_type)
        _check_key_support(self.version, key_type, pin_policy, touch_policy)
        if key_type.algorithm == ALGORITHM.RSA and (
            (4, 2, 0) <= self.version < (4, 3, 5)
        ):
            raise NotSupportedError("RSA key generation not supported on this YubiKey")
        data = Tlv(TAG_GEN_ALGORITHM, int_to_bytes(key_type))
        if pin_policy:
            data += Tlv(TAG_PIN_POLICY, int_to_bytes(pin_policy))
        if touch_policy:
            data += Tlv(TAG_TOUCH_POLICY, int_to_bytes(touch_policy))
        response = self.send_apdu(0, INS_GENERATE_ASYMMETRIC, 0, slot, Tlv(0xAC, data))
        return _parse_device_public_key(key_type, Tlv.unwrap(0x7F49, response))

    def attest_key(self, slot):
        if self.version < (4, 3, 0):
            raise NotSupportedError("Attestation requires YubiKey 4.3 or later")
        response = self.send_apdu(0, INS_ATTEST, slot, 0)
        return x509.load_der_x509_certificate(response, default_backend())

    def _change_reference(self, ins, p2, value1, value2):
        try:
            self.send_apdu(0, ins, 0, p2, _pin_bytes(value1) + _pin_bytes(value2))
        except ApduError as e:
            retries = _retries_from_sw(self.version, e.sw)
            if retries is None:
                raise
            if p2 == PIN_P2:
                self._current_pin_retries = retries
            raise InvalidPinError(retries)

    def _get_pin_puk_metadata(self, p2):
        if self.version < (5, 3, 0):
            raise NotSupportedError("PIN/PUK metadata requires version 5.3.0 or later.")
        data = Tlv.parse_dict(self.send_apdu(0, INS_GET_METADATA, 0, p2))
        attempts = data[TAG_METADATA_RETRIES]
        return PinMetadata(
            data[TAG_METADATA_IS_DEFAULT] != b"\0",
            six.indexbytes(attempts, INDEX_RETRIES_TOTAL),
            six.indexbytes(attempts, INDEX_RETRIES_REMAINING),
        )

    def _use_private_key(self, slot, key_type, message, exponentiation):
        try:
            response = self.send_apdu(
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
            return Tlv.unwrap(TAG_AUTH_RESPONSE, Tlv.unwrap(TAG_DYN_AUTH, response,),)
        except ApduError as e:
            if e.sw == SW.INCORRECT_PARAMETERS:
                raise e  # TODO: Different error, No key?
            raise
