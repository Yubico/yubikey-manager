from .core import (
    int2bytes,
    bytes2int,
    Tlv,
    AID,
    NotSupportedError,
    BadResponseError,
)
from .core.iso7816 import Iso7816Application

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from six.moves.urllib.parse import unquote, urlparse, parse_qs
from functools import total_ordering
from enum import IntEnum, unique
from collections import namedtuple
from base64 import b64encode, b32decode
from time import time

import struct
import six
import os
import re


# TLV tags for credential data
TAG_NAME = 0x71
TAG_NAME_LIST = 0x72
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
TAG_TRUNCATED = 0x76
TAG_HOTP = 0x77
TAG_PROPERTY = 0x78
TAG_VERSION = 0x79
TAG_IMF = 0x7A
TAG_TOUCH = 0x7C

# Instruction bytes for commands
INS_LIST = 0xA1
INS_PUT = 0x01
INS_DELETE = 0x02
INS_SET_CODE = 0x03
INS_RESET = 0x04
INS_RENAME = 0x05
INS_CALCULATE = 0xA2
INS_VALIDATE = 0xA3
INS_CALCULATE_ALL = 0xA4
INS_SEND_REMAINING = 0xA5

TOTP_ID_PATTERN = re.compile(r"^((\d+)/)?(([^:]+):)?(.+)$")

MASK_ALGO = 0x0F
MASK_TYPE = 0xF0

DEFAULT_PERIOD = 30
DEFAULT_DIGITS = 6
CHALLENGE_LEN = 8
HMAC_MINIMUM_KEY_SIZE = 14


@unique
class HASH_ALGORITHM(IntEnum):
    SHA1 = 0x01
    SHA256 = 0x02
    SHA512 = 0x03


@unique
class OATH_TYPE(IntEnum):
    HOTP = 0x10
    TOTP = 0x20


PROP_REQUIRE_TOUCH = 0x02


def parse_b32_key(key):
    key = key.upper().replace(" ", "")
    key += "=" * (-len(key) % 8)  # Support unpadded
    return b32decode(key)


class OathApplicationInfo(namedtuple("OathApplicationInfo", ["version", "device_id"])):
    __slots__ = ()


def _parse_select(response):
    data = Tlv.parse_dict(response)
    return (
        OathApplicationInfo(tuple(data[TAG_VERSION]), _get_device_id(data[TAG_NAME])),
        data.get(TAG_NAME),
        data.get(TAG_CHALLENGE),
    )


class CredentialData(
    namedtuple(
        "CredentialData",
        [
            "name",
            "oath_type",
            "hash_algorithm",
            "secret",
            "digits",
            "period",
            "counter",
            "issuer",
        ],
    )
):
    __slots__ = ()

    @classmethod
    def parse_uri(cls, uri):
        parsed = urlparse(uri.strip())
        if parsed.scheme != "otpauth":
            raise ValueError("Invalid URI scheme")

        params = dict((k, v[0]) for k, v in parse_qs(parsed.query).items())
        issuer = None
        name = unquote(parsed.path)[1:]  # Unquote and strip leading /
        if ":" in name:
            issuer, name = name.split(":", 1)

        return cls(
            name=name,
            oath_type=OATH_TYPE[parsed.hostname.upper()],
            hash_algorithm=HASH_ALGORITHM[params.get("algorithm", "SHA1").upper()],
            secret=parse_b32_key(params["secret"]),
            digits=int(params.get("digits", DEFAULT_DIGITS)),
            period=int(params.get("period", DEFAULT_PERIOD)),
            counter=int(params.get("counter", 0)),
            issuer=params.get("issuer", issuer),
        )

    def get_id(self):
        return _format_cred_id(self.issuer, self.name, self.oath_type, self.period)


class Code(namedtuple("Code", ["value", "valid_from", "valid_to"])):
    __slots__ = ()


@total_ordering
class _CredentialOrdering(object):
    __slots__ = ()

    def __lt__(self, other):
        a = ((self.issuer or self.name).lower(), self.name.lower())
        b = ((other.issuer or other.name).lower(), other.name.lower())
        return a < b


class Credential(
    _CredentialOrdering,
    namedtuple(
        "Credential",
        ["device_id", "id", "issuer", "name", "oath_type", "period", "touch_required"],
    ),
):
    __slots__ = ()

    def __eq__(self, other):
        return (
            isinstance(other, type(self))
            and self.device_id == other.device_id
            and self.id == other.id
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.device_id, self.id))


def _format_cred_id(issuer, name, oath_type, period=DEFAULT_PERIOD):
    cred_id = ""
    if oath_type == OATH_TYPE.TOTP and period != DEFAULT_PERIOD:
        cred_id += "%d/" % period
    if issuer:
        cred_id += issuer + ":"
    cred_id += name
    return cred_id.encode("utf-8")


def _parse_cred_id(cred_id, oath_type):
    data = cred_id.decode("utf-8")
    if oath_type == OATH_TYPE.TOTP:
        match = TOTP_ID_PATTERN.match(data)
        if match:
            period_str = match.group(2)
            return (
                match.group(4),
                match.group(5),
                int(period_str) if period_str else DEFAULT_PERIOD,
            )
        else:
            return None, data, DEFAULT_PERIOD
    else:
        if ":" in data:
            issuer, data = data.split(":", 1)
        else:
            issuer = None
    return issuer, data, None


def _get_device_id(salt):
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(salt)
    d = h.finalize()[:16]
    return b64encode(d).replace(b"=", b"").decode()


def _hmac_sha1(key, message):
    h = hmac.HMAC(key, hashes.SHA1(), default_backend())  # nosec
    h.update(message)
    return h.finalize()


def _derive_key(salt, passphrase):
    kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())  # nosec
    return kdf.derive(passphrase.encode("utf-8"))


def _hmac_shorten_key(key, algo):
    h = getattr(hashes, algo.name)()

    if len(key) > h.block_size:
        h = hashes.Hash(h, default_backend())
        h.update(key)
        key = h.finalize()
    return key


def _get_challenge(timestamp, period):
    time_step = timestamp // period
    return struct.pack(">q", time_step)


def _format_code(credential, timestamp, truncated):
    if credential.oath_type == OATH_TYPE.TOTP:
        time_step = timestamp // credential.period
        valid_from = time_step * credential.period
        valid_to = (time_step + 1) * credential.period
    else:  # HOTP
        valid_from = timestamp
        valid_to = float("Inf")
    digits = six.indexbytes(truncated, 0)

    return Code(
        str(bytes2int(truncated[1:]) & 0x7FFFFFFF).rjust(digits, "0"),
        valid_from,
        valid_to,
    )


class OathApplication(Iso7816Application):
    def __init__(self, connection):
        super(OathApplication, self).__init__(AID.OATH, connection, INS_SEND_REMAINING)
        self._app_info, self._salt, self._challenge = _parse_select(self.select())
        self.enable_touch_workaround(self.info.version)

    @property
    def info(self):
        return self._app_info

    @property
    def locked(self):
        return self._challenge is not None

    def reset(self):
        self.send_apdu(0, INS_RESET, 0xDE, 0xAD)
        self._app_info, self._salt, self._challenge = _parse_select(self.select())

    def derive_key(self, password):
        return _derive_key(self._salt, password)

    def validate(self, key):
        response = _hmac_sha1(key, self._challenge)
        challenge = os.urandom(8)
        data = Tlv(TAG_RESPONSE, response) + Tlv(TAG_CHALLENGE, challenge)
        resp = self.send_apdu(0, INS_VALIDATE, 0, 0, data)
        verification = _hmac_sha1(key, challenge)
        if not constant_time.bytes_eq(Tlv.unpack(TAG_RESPONSE, resp), verification):
            raise BadResponseError(
                "Response from validation does not match verification!"
            )
        self._challenge = None

    def set_key(self, key):
        challenge = os.urandom(8)
        response = _hmac_sha1(key, challenge)
        self.send_apdu(
            0,
            INS_SET_CODE,
            0,
            0,
            (
                Tlv(TAG_KEY, int2bytes(OATH_TYPE.TOTP | HASH_ALGORITHM.SHA1) + key)
                + Tlv(TAG_CHALLENGE, challenge)
                + Tlv(TAG_RESPONSE, response)
            ),
        )

    def unset_key(self):
        self.send_apdu(0, INS_SET_CODE, 0, 0, Tlv(TAG_KEY))

    def put_credential(self, credential_data, touch_required=False):
        d = credential_data
        cred_id = d.get_id()
        secret = _hmac_shorten_key(d.secret, d.hash_algorithm)
        secret = secret.ljust(HMAC_MINIMUM_KEY_SIZE, b"\0")
        data = Tlv(TAG_NAME, cred_id) + Tlv(
            TAG_KEY,
            struct.pack("<BB", d.oath_type | d.hash_algorithm, d.digits) + secret,
        )

        if touch_required:
            data += struct.pack(b">BB", TAG_PROPERTY, PROP_REQUIRE_TOUCH)

        if d.counter > 0:
            data += Tlv(TAG_IMF, struct.pack(">I", d.counter))

        self.send_apdu(0, INS_PUT, 0, 0, data)
        return Credential(
            self.info.device_id,
            cred_id,
            d.issuer,
            d.name,
            d.oath_type,
            d.period,
            touch_required,
        )

    def rename_credential(self, credential_id, name, issuer=None):
        if self.info.version < (5, 3, 1):
            raise NotSupportedError("Operation requires YubiKey 5.3.1 or later")
        issuer, name, period = _parse_cred_id(credential_id, OATH_TYPE.TOTP)
        new_id = _format_cred_id(issuer, name, OATH_TYPE.TOTP, period)
        self.send_apdu(
            0, INS_RENAME, 0, 0, Tlv(TAG_NAME, credential_id) + Tlv(TAG_NAME, new_id)
        )
        return new_id

    def list_credentials(self):
        creds = []
        for tlv in Tlv.parse_list(self.send_apdu(0, INS_LIST, 0, 0)):
            data = Tlv.unpack(TAG_NAME_LIST, tlv)
            oath_type = OATH_TYPE(MASK_TYPE & six.indexbytes(data, 0))
            cred_id = data[1:]
            issuer, name, period = _parse_cred_id(cred_id, oath_type)
            creds.append(
                Credential(
                    self.info.device_id, cred_id, issuer, name, oath_type, period, None
                )
            )
        return creds

    def calculate(self, credential_id, challenge):
        resp = Tlv.unpack(
            TAG_RESPONSE,
            self.send_apdu(
                0,
                INS_CALCULATE,
                0,
                0,
                Tlv(TAG_NAME, credential_id) + Tlv(TAG_CHALLENGE, challenge),
            ),
        )
        return resp[1:]

    def delete_credential(self, credential_id):
        self.send_apdu(0, INS_DELETE, 0, 0, Tlv(TAG_NAME, credential_id))

    def calculate_all(self, timestamp=None):
        timestamp = int(timestamp or time())
        challenge = _get_challenge(timestamp, DEFAULT_PERIOD)

        entries = {}
        data = Tlv.parse_list(
            self.send_apdu(0, INS_CALCULATE_ALL, 0, 1, Tlv(TAG_CHALLENGE, challenge))
        )
        while data:
            cred_id = Tlv.unpack(TAG_NAME, data.pop(0))
            tlv = data.pop(0)
            resp_tag = tlv.tag
            oath_type = OATH_TYPE.HOTP if resp_tag == TAG_HOTP else OATH_TYPE.TOTP
            touch = resp_tag == TAG_TOUCH
            issuer, name, period = _parse_cred_id(cred_id, oath_type)

            credential = Credential(
                self.info.device_id, cred_id, issuer, name, oath_type, period, touch
            )

            code = None  # Will be None for HOTP and touch
            if oath_type == OATH_TYPE.TOTP:
                if period != DEFAULT_PERIOD:
                    # Non-standard period, recalculate
                    code = self.calculate_code(credential, timestamp)
                elif resp_tag == TAG_TRUNCATED:
                    code = _format_code(credential, timestamp, tlv.value)
            entries[credential] = code

        return entries

    def calculate_code(self, credential, timestamp=None):
        if credential.device_id != self.info.device_id:
            raise ValueError("Credential does not belong to this YubiKey")

        timestamp = int(timestamp or time())
        if credential.oath_type == OATH_TYPE.TOTP:
            challenge = _get_challenge(timestamp, credential.period)
        else:  # HOTP
            challenge = b""

        response = Tlv.unpack(
            TAG_TRUNCATED,
            self.send_apdu(
                0,
                INS_CALCULATE,
                0,
                0x01,  # Truncate
                Tlv(TAG_NAME, credential.id) + Tlv(TAG_CHALLENGE, challenge),
            ),
        )
        return _format_code(credential, timestamp, response)
