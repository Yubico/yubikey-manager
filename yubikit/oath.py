from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import IntEnum, unique
from functools import total_ordering
from time import time
from typing import Mapping
from urllib.parse import parse_qs, unquote, urlparse

from _ykman_native.oath import (  # noqa: F401
    build_put_data as _build_put_data,
)
from _ykman_native.oath import (
    build_set_key_data as _build_set_key_data,
)
from _ykman_native.oath import (
    build_validate_data as _build_validate_data,
)
from _ykman_native.oath import (
    derive_key as _derive_key_native,
)
from _ykman_native.oath import (
    format_code as _format_code_native,
)
from _ykman_native.oath import (
    format_cred_id as _format_cred_id_native,
)
from _ykman_native.oath import (
    get_challenge as _get_challenge_native,
)
from _ykman_native.oath import (
    get_device_id as _get_device_id_native,
)
from _ykman_native.oath import (
    hmac_sha1 as _hmac_sha1_native,
)
from _ykman_native.oath import (
    hmac_shorten_key as _hmac_shorten_key_native,
)
from _ykman_native.oath import (
    hmac_verify as _hmac_verify,
)
from _ykman_native.oath import (
    parse_b32_key,
)
from _ykman_native.oath import (
    parse_cred_id as _parse_cred_id_native,
)
from _ykman_native.sessions import OathSession as _NativeOathSession

from .core import (
    BadResponseError,
    Tlv,
    Version,
    _override_version,
    require_version,
)
from .core.smartcard import ScpKeyParams, SmartCardConnection, SmartCardProtocol

logger = logging.getLogger(__name__)


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

TOTP_ID_PATTERN = None  # No longer used, parsing is in Rust

MASK_ALGO = 0x0F
MASK_TYPE = 0xF0

DEFAULT_PERIOD = 30
DEFAULT_DIGITS = 6
DEFAULT_IMF = 0
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


def _parse_select(response):
    data = Tlv.parse_dict(response)
    return (
        _override_version.patch(Version.from_bytes(data[TAG_VERSION])),
        data.get(TAG_NAME),
        data.get(TAG_CHALLENGE),
    )


@dataclass
class CredentialData:
    """An object holding OATH credential data."""

    name: str
    oath_type: OATH_TYPE
    hash_algorithm: HASH_ALGORITHM
    secret: bytes
    digits: int = DEFAULT_DIGITS
    period: int = DEFAULT_PERIOD
    counter: int = DEFAULT_IMF
    issuer: str | None = None

    @classmethod
    def parse_uri(cls, uri: str) -> CredentialData:
        """Parse OATH credential data from URI.

        :param uri: The URI to parse from.
        """
        parsed = urlparse(uri.strip())
        if parsed.scheme != "otpauth":
            raise ValueError("Invalid URI scheme")

        if parsed.hostname is None:
            raise ValueError("Missing OATH type")
        oath_type = OATH_TYPE[parsed.hostname.upper()]

        params = dict((k, v[0]) for k, v in parse_qs(parsed.query).items())
        issuer = None
        name = unquote(parsed.path)[1:]  # Unquote and strip leading /
        if ":" in name:
            issuer, name = name.split(":", 1)

        return cls(
            name=name,
            oath_type=oath_type,
            hash_algorithm=HASH_ALGORITHM[params.get("algorithm", "SHA1").upper()],
            secret=parse_b32_key(params["secret"]),
            digits=int(params.get("digits", DEFAULT_DIGITS)),
            period=int(params.get("period", DEFAULT_PERIOD)),
            counter=int(params.get("counter", DEFAULT_IMF)),
            issuer=params.get("issuer", issuer),
        )

    def get_id(self) -> bytes:
        return bytes(
            _format_cred_id(self.issuer, self.name, int(self.oath_type), self.period)
        )


@dataclass
class Code:
    """An OATH code object."""

    value: str
    valid_from: int
    valid_to: int


@total_ordering
@dataclass(order=False, frozen=True)
class Credential:
    """An OATH credential object."""

    device_id: str
    id: bytes
    issuer: str | None
    name: str
    oath_type: OATH_TYPE
    period: int
    touch_required: bool | None

    def __lt__(self, other):
        a = ((self.issuer or self.name).lower(), self.name.lower())
        b = ((other.issuer or other.name).lower(), other.name.lower())
        return a < b

    def __eq__(self, other):
        return (
            isinstance(other, type(self))
            and self.device_id == other.device_id
            and self.id == other.id
        )

    def __hash__(self):
        return hash((self.device_id, self.id))


def _format_cred_id(issuer, name, oath_type, period=DEFAULT_PERIOD):
    return bytes(_format_cred_id_native(issuer, name, int(oath_type), period))


def _parse_cred_id(cred_id, oath_type):
    return _parse_cred_id_native(cred_id, int(oath_type))


def _get_device_id(salt):
    return _get_device_id_native(salt)


def _hmac_sha1(key, message):
    return bytes(_hmac_sha1_native(key, message))


def _derive_key(salt, passphrase):
    return bytes(_derive_key_native(salt, passphrase))


def _hmac_shorten_key(key, algo):
    return bytes(_hmac_shorten_key_native(key, int(algo)))


def _get_challenge(timestamp, period):
    return bytes(_get_challenge_native(timestamp, period))


def _format_code(credential, timestamp, truncated):
    code_str, valid_from, valid_to = _format_code_native(
        int(credential.oath_type), credential.period, timestamp, bytes(truncated)
    )
    return Code(code_str, valid_from, valid_to)


class OathSession:
    """A session with the OATH application.

    Delegates to the Rust OathSession implementation via PyO3.
    """

    def __init__(
        self,
        connection: SmartCardConnection,
        scp_key_params: ScpKeyParams | None = None,
    ):
        native = _NativeOathSession(connection, scp_key_params)
        self._native = native
        self._version = _override_version.patch(Version(*native.version))
        if self._version != Version(*native.version):
            native.version = tuple(self._version)
        self._device_id = native.device_id
        self._has_key = native.has_key
        self._challenge = b"" if native.locked else None
        self.protocol = SmartCardProtocol(connection, INS_SEND_REMAINING)

        logger.debug(
            f"OATH session initialized (version={self.version}, "
            f"has_key={self._has_key})"
        )

    @property
    def version(self) -> Version:
        """The version of the OATH application."""
        return self._version

    @property
    def device_id(self) -> str:
        """The device ID.

        A random static identifier that is re-generated on reset.
        """
        return self._device_id

    @property
    def has_key(self) -> bool:
        """If True, the YubiKey has an access key set."""
        if self._native:
            return self._native.has_key
        return self._has_key

    @property
    def locked(self) -> bool:
        """If True, the OATH application is currently locked via an access key."""
        if self._native:
            return self._native.locked
        return self._challenge is not None

    def reset(self) -> None:
        """Perform a factory reset on the OATH application."""
        if self._native:
            self._native.reset()
            self._has_key = self._native.has_key
            self._device_id = self._native.device_id
        logger.info("OATH application data reset performed")

    def derive_key(self, password: str) -> bytes:
        """Derive an access key from a password.

        :param password: The derivation password.
        """
        if self._native:
            return bytes(self._native.derive_key(password))
        raise RuntimeError("Native session not available")

    def validate(self, key: bytes) -> None:
        """Validate authentication with access key.

        This unlocks the session for use.

        :param key: The access key.
        """
        logger.debug("Unlocking session")
        if self._native:
            self._native.validate(key)
            self._challenge = None
        else:
            data = bytes(_build_validate_data(key, self._challenge, os.urandom(8)))
            _, rest = Tlv.parse_from(data)
            host_challenge = Tlv(rest).value
            resp = self.protocol.send_apdu(0, INS_VALIDATE, 0, 0, data)
            if not _hmac_verify(key, host_challenge, Tlv.unpack(TAG_RESPONSE, resp)):
                raise BadResponseError(
                    "Response from validation does not match verification!"
                )
            self._challenge = None

    def set_key(self, key: bytes) -> None:
        """Set an access key for authentication.

        :param key: The access key.
        """
        if self._native:
            self._native.set_key(key)
            self._has_key = True
        else:
            challenge = os.urandom(8)
            data = bytes(_build_set_key_data(key, challenge))
            self.protocol.send_apdu(0, INS_SET_CODE, 0, 0, data)
            self._has_key = True
        logger.info("New access code set")

    def unset_key(self) -> None:
        """Remove the access key.

        This removes the need to authentication a session before using it.
        """
        if self._native:
            self._native.unset_key()
        else:
            self.protocol.send_apdu(0, INS_SET_CODE, 0, 0, Tlv(TAG_KEY))
        logger.info("Access code removed")
        self._has_key = False

    def put_credential(
        self, credential_data: CredentialData, touch_required: bool = False
    ) -> Credential:
        """Add an OATH credential.

        :param credential_data: The credential data.
        :param touch_required: The touch policy.
        """
        d = credential_data
        if self._native:
            result = self._native.put_credential(
                name=d.name,
                oath_type=int(d.oath_type),
                hash_algorithm=int(d.hash_algorithm),
                secret=d.secret,
                digits=d.digits,
                period=d.period,
                counter=d.counter,
                issuer=d.issuer,
                touch_required=touch_required,
            )
            logger.info("Credential imported")
            return Credential(
                result[0],
                result[1],
                result[2],
                result[3],
                OATH_TYPE(result[4]),
                result[5],
                result[6],
            )

        cred_id = d.get_id()
        data = bytes(
            _build_put_data(
                cred_id,
                int(d.oath_type),
                int(d.hash_algorithm),
                d.digits,
                d.secret,
                touch_required,
                d.counter,
            )
        )
        self.protocol.send_apdu(0, INS_PUT, 0, 0, data)
        logger.info("Credential imported")
        return Credential(
            self.device_id,
            cred_id,
            d.issuer,
            d.name,
            d.oath_type,
            d.period,
            touch_required,
        )

    def rename_credential(
        self, credential_id: bytes, name: str, issuer: str | None = None
    ) -> bytes:
        """Rename a OATH credential.

        :param credential_id: The id of the credential.
        :param name: The new name of the credential.
        :param issuer: The credential issuer.
        """
        logger.debug(f"Renaming credential '{credential_id!r}' to '{issuer}:{name}'")
        if self._native:
            result = self._native.rename_credential(credential_id, name, issuer)
            logger.info("Credential renamed")
            return bytes(result)

        require_version(self.version, (5, 3, 1))
        _, _, period = _parse_cred_id(credential_id, OATH_TYPE.TOTP)
        new_id = _format_cred_id(issuer, name, OATH_TYPE.TOTP, period)
        self.protocol.send_apdu(
            0, INS_RENAME, 0, 0, Tlv(TAG_NAME, credential_id) + Tlv(TAG_NAME, new_id)
        )
        logger.info("Credential renamed")
        return new_id

    def list_credentials(self) -> list[Credential]:
        """List OATH credentials."""
        logger.debug("Listing OATH credentials...")
        if self._native:
            raw = self._native.list_credentials()
            return [
                Credential(r[0], r[1], r[2], r[3], OATH_TYPE(r[4]), r[5], r[6])
                for r in raw
            ]

        creds = []
        for tlv in Tlv.parse_list(self.protocol.send_apdu(0, INS_LIST, 0, 0)):
            data = Tlv.unpack(TAG_NAME_LIST, tlv)
            oath_type = OATH_TYPE(MASK_TYPE & data[0])
            cred_id = data[1:]
            issuer, name, period = _parse_cred_id(cred_id, oath_type)
            creds.append(
                Credential(
                    self.device_id, cred_id, issuer, name, oath_type, period, None
                )
            )
        return creds

    def calculate(self, credential_id: bytes, challenge: bytes) -> bytes:
        """Perform a calculate for an OATH credential.

        :param credential_id: The id of the credential.
        :param challenge: The challenge.
        """
        logger.debug(f"Calculating response for credential: {credential_id!r}")
        if self._native:
            return bytes(self._native.calculate(credential_id, challenge))

        resp = Tlv.unpack(
            TAG_RESPONSE,
            self.protocol.send_apdu(
                0,
                INS_CALCULATE,
                0,
                0,
                Tlv(TAG_NAME, credential_id) + Tlv(TAG_CHALLENGE, challenge),
            ),
        )
        return resp[1:]

    def delete_credential(self, credential_id: bytes) -> None:
        """Delete an OATH credential.

        :param credential_id: The id of the credential.
        """
        logger.debug(f"Deleting crededential: {credential_id!r}")
        if self._native:
            self._native.delete_credential(credential_id)
        else:
            self.protocol.send_apdu(0, INS_DELETE, 0, 0, Tlv(TAG_NAME, credential_id))
        logger.info("Credential deleted")

    def calculate_all(
        self, timestamp: int | None = None
    ) -> Mapping[Credential, Code | None]:
        """Calculate codes for all OATH credentials on the YubiKey.

        This excludes credentials which require touch as well as HOTP credentials.

        :param timestamp: A timestamp used for the TOTP challenge.
        """
        timestamp = int(timestamp or time())

        if self._native:
            raw = self._native.calculate_all(timestamp)
            entries: dict[Credential, Code | None] = {}
            for r in raw:
                cred = Credential(r[0], r[1], r[2], r[3], OATH_TYPE(r[4]), r[5], r[6])
                if r[7] is not None:
                    code: Code | None = Code(r[7], r[8], r[9])
                else:
                    code = None
                entries[cred] = code
            return entries

        challenge = bytes(_get_challenge(timestamp, DEFAULT_PERIOD))
        logger.debug(f"Calculating all codes for time={timestamp}")

        entries = {}
        data = Tlv.parse_list(
            self.protocol.send_apdu(
                0, INS_CALCULATE_ALL, 0, 1, Tlv(TAG_CHALLENGE, challenge)
            )
        )
        while data:
            cred_id = Tlv.unpack(TAG_NAME, data.pop(0))
            tlv = data.pop(0)
            resp_tag = tlv.tag
            oath_type = OATH_TYPE.HOTP if resp_tag == TAG_HOTP else OATH_TYPE.TOTP
            touch = resp_tag == TAG_TOUCH
            issuer, name, period = _parse_cred_id(cred_id, oath_type)

            credential = Credential(
                self.device_id, cred_id, issuer, name, oath_type, period, touch
            )

            code = None  # Will be None for HOTP and touch
            if resp_tag == TAG_TRUNCATED:  # Only TOTP, no-touch here
                if period == DEFAULT_PERIOD:
                    code = _format_code(credential, timestamp, tlv.value)
                else:
                    # Non-standard period, recalculate
                    logger.debug(f"Recalculating code for period={period}")
                    code = self.calculate_code(credential, timestamp)
            entries[credential] = code

        return entries

    def calculate_code(
        self, credential: Credential, timestamp: int | None = None
    ) -> Code:
        """Calculate code for an OATH credential.

        :param credential: The credential object.
        :param timestamp: The timestamp.
        """
        if credential.device_id != self.device_id:
            raise ValueError("Credential does not belong to this YubiKey")

        timestamp = int(timestamp or time())

        if self._native:
            result = self._native.calculate_code(
                device_id=credential.device_id,
                cred_id=credential.id,
                issuer=credential.issuer,
                name=credential.name,
                oath_type=int(credential.oath_type),
                period=credential.period,
                touch_required=credential.touch_required,
                timestamp=timestamp,
            )
            return Code(result[0], result[1], result[2])

        if credential.oath_type == OATH_TYPE.TOTP:
            logger.debug(
                f"Calculating TOTP code for time={timestamp}, "
                f"period={credential.period}"
            )
            challenge = bytes(_get_challenge(timestamp, credential.period))
        else:  # HOTP
            logger.debug("Calculating HOTP code")
            challenge = b""

        response = Tlv.unpack(
            TAG_TRUNCATED,
            self.protocol.send_apdu(
                0,
                INS_CALCULATE,
                0,
                0x01,  # Truncate
                Tlv(TAG_NAME, credential.id) + Tlv(TAG_CHALLENGE, challenge),
            ),
        )
        return _format_code(credential, timestamp, response)
