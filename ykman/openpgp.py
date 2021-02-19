# Copyright (c) 2015 Yubico AB
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

from yubikit.core import (
    AID,
    Tlv,
    NotSupportedError,
    require_version,
    int2bytes,
    bytes2int,
)
from yubikit.core.smartcard import SmartCardConnection, SmartCardProtocol, ApduError, SW

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from enum import Enum, IntEnum, unique
from collections import namedtuple
from dataclasses import dataclass
from typing import Optional
import time
import struct
import logging

logger = logging.getLogger(__name__)


_KeySlot = namedtuple(
    "KeySlot",
    [
        "value",
        "index",
        "key_id",
        "fingerprint",
        "gen_time",
        "uif",  # touch policy
        "crt",  # Control Reference Template
    ],
)


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

    def __str__(self):
        if self == TOUCH_MODE.OFF:
            return "Off"
        elif self == TOUCH_MODE.ON:
            return "On"
        elif self == TOUCH_MODE.FIXED:
            return "On (fixed)"
        elif self == TOUCH_MODE.CACHED:
            return "Cached"
        elif self == TOUCH_MODE.CACHED_FIXED:
            return "Cached (fixed)"


@unique
class INS(IntEnum):  # noqa: N801
    GET_DATA = 0xCA
    GET_VERSION = 0xF1
    SET_PIN_RETRIES = 0xF2
    VERIFY = 0x20
    TERMINATE = 0xE6
    ACTIVATE = 0x44
    GENERATE_ASYM = 0x47
    PUT_DATA = 0xDA
    PUT_DATA_ODD = 0xDB
    GET_ATTESTATION = 0xFB
    SEND_REMAINING = 0xC0
    SELECT_DATA = 0xA5


PinRetries = namedtuple("PinRetries", ["pin", "reset", "admin"])


PW1 = 0x81
PW3 = 0x83
INVALID_PIN = b"\0" * 8
TOUCH_METHOD_BUTTON = 0x20


@unique
class DO(IntEnum):
    AID = 0x4F
    PW_STATUS = 0xC4
    CARDHOLDER_CERTIFICATE = 0x7F21
    ATT_CERTIFICATE = 0xFC
    KDF = 0xF9


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
    if isinstance(key, rsa.RSAPrivateKey):
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

    if isinstance(key, rsa.RSAPrivateKey):
        private_numbers = key.private_numbers()
        ln = (key.key_size // 8) // 2

        e = Tlv(0x91, b"\x01\x00\x01")  # e=65537
        p = Tlv(0x92, int2bytes(private_numbers.p, ln))
        q = Tlv(0x93, int2bytes(private_numbers.q, ln))
        values = (e, p, q)
        if crt:
            dp = Tlv(0x94, int2bytes(private_numbers.dmp1, ln))
            dq = Tlv(0x95, int2bytes(private_numbers.dmq1, ln))
            qinv = Tlv(0x96, int2bytes(private_numbers.iqmp, ln))
            n = Tlv(0x97, int2bytes(private_numbers.public_numbers.n, 2 * ln))
            values += (dp, dq, qinv, n)

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        private_numbers = key.private_numbers()
        ln = key.key_size // 8

        privkey = Tlv(0x92, int2bytes(private_numbers.private_value, ln))
        values = (privkey,)

    elif _get_curve_name(key) in ("ed25519", "x25519"):
        privkey = Tlv(
            0x92, key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        values = (privkey,)

    return Tlv(0x4D, key_slot.crt + _pack_tlvs(values))


@unique
class HashAlgorithm(IntEnum):
    SHA256 = 0x08
    SHA512 = 0x0A

    def create_digest(self):
        algorithm = getattr(hashes, self.name)
        return hashes.Hash(algorithm(), default_backend())


@unique
class KdfAlgorithm(IntEnum):
    NONE = 0x00
    KDF_ITERSALTED_S2K = 0x03


def _kdf_none(pin, salt, hash_algorithm, iteration_count):
    return pin


def _kdf_itersalted_s2k(pin, salt, hash_algorithm, iteration_count):
    data = salt + pin
    digest = hash_algorithm.create_digest()
    # Although the field is called "iteration count", it's actually
    # the number of bytes to be passed to the hash function, which
    # is called only once. Go figure!
    data_count, trailing_bytes = divmod(iteration_count, len(data))
    for _ in range(data_count):
        digest.update(data)
    digest.update(data[:trailing_bytes])
    return digest.finalize()


_KDFS = {
    KdfAlgorithm.NONE: _kdf_none,
    KdfAlgorithm.KDF_ITERSALTED_S2K: _kdf_itersalted_s2k,
}


def _parse_int(data, tag, func=lambda x: x, default=None):
    return func(int.from_bytes(data[tag], "big")) if tag in data else default


@dataclass
class KdfData:
    kdf_algorithm: KdfAlgorithm
    hash_algorithm: Optional[HashAlgorithm]
    iteration_count: Optional[int]
    pw1_salt_bytes: Optional[bytes]
    pw2_salt_bytes: Optional[bytes]
    pw3_salt_bytes: Optional[bytes]
    pw1_initial_hash: Optional[bytes]
    pw3_initial_hash: Optional[bytes]

    def process(self, pw, pin):
        kdf = _KDFS[self.kdf_algorithm]
        if pw == PW1:
            salt = self.pw1_salt_bytes
        elif pw == PW3:
            salt = self.pw3_salt_bytes or self.pw1_salt_bytes
        else:
            raise ValueError("Invalid value for pw")
        return kdf(pin, salt, self.hash_algorithm, self.iteration_count)

    @classmethod
    def parse(cls, data: bytes) -> "KdfData":
        fields = Tlv.parse_dict(data)
        return cls(
            _parse_int(fields, 0x81, KdfAlgorithm, KdfAlgorithm.NONE),
            _parse_int(fields, 0x82, HashAlgorithm),
            _parse_int(fields, 0x83),
            fields.get(0x84),
            fields.get(0x85),
            fields.get(0x86),
            fields.get(0x87),
            fields.get(0x88),
        )


class OpenPgpController(object):
    def __init__(self, connection: SmartCardConnection):
        protocol = SmartCardProtocol(connection)
        self._app = protocol
        try:
            protocol.select(AID.OPENPGP)
        except ApduError as e:
            if e.sw in (SW.NO_INPUT_DATA, SW.CONDITIONS_NOT_SATISFIED):
                protocol.send_apdu(0, INS.ACTIVATE, 0, 0)
                protocol.select(AID.OPENPGP)
            else:
                raise
        self._version = self._read_version()

    @property
    def version(self):
        return self._version

    def _get_data(self, do):
        return self._app.send_apdu(0, INS.GET_DATA, do >> 8, do & 0xFF)

    def _put_data(self, do, data):
        self._app.send_apdu(0, INS.PUT_DATA, do >> 8, do & 0xFF, data)

    def _select_certificate(self, key_slot):
        self._app.send_apdu(
            0,
            INS.SELECT_DATA,
            3 - key_slot.index,
            0x04,
            Tlv(0, Tlv(0x60, Tlv(0x5C, b"\x7f\x21")))[1:],
        )

    def _read_version(self):
        bcd_hex = self._app.send_apdu(0, INS.GET_VERSION, 0, 0).hex()
        return tuple(int(bcd_hex[i : i + 2]) for i in range(0, 6, 2))

    def get_openpgp_version(self):
        data = self._get_data(DO.AID)
        return data[6], data[7]

    def get_remaining_pin_tries(self):
        data = self._get_data(DO.PW_STATUS)
        return PinRetries(*data[4:7])

    def _block_pins(self):
        retries = self.get_remaining_pin_tries()

        for _ in range(retries.pin):
            try:
                self._app.send_apdu(0, INS.VERIFY, 0, PW1, INVALID_PIN)
            except ApduError:
                pass
        for _ in range(retries.admin):
            try:
                self._app.send_apdu(0, INS.VERIFY, 0, PW3, INVALID_PIN)
            except ApduError:
                pass

    def reset(self):
        if self.version < (1, 0, 6):
            raise ValueError("Resetting OpenPGP data requires version 1.0.6 or later.")
        self._block_pins()
        self._app.send_apdu(0, INS.TERMINATE, 0, 0)
        self._app.send_apdu(0, INS.ACTIVATE, 0, 0)

    def _get_kdf(self):
        try:
            data = self._get_data(DO.KDF)
        except ApduError:
            data = b""
        return KdfData.parse(data)

    def _verify(self, pw, pin):
        try:
            pin = self._get_kdf().process(pw, pin.encode())
            self._app.send_apdu(0, INS.VERIFY, 0, pw, pin)
        except ApduError:
            pw_remaining = self.get_remaining_pin_tries()[pw - PW1]
            raise ValueError(f"Invalid PIN, {pw_remaining} tries remaining.")

    def verify_pin(self, pin):
        self._verify(PW1, pin)

    def verify_admin(self, admin_pin):
        self._verify(PW3, admin_pin)

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
        data = self._get_data(key_slot.uif)
        return TOUCH_MODE(data[0])

    def set_touch(self, key_slot, mode):
        """Requires Admin PIN verification."""
        if not self.supported_touch_policies:
            raise ValueError("Touch policy is available on YubiKey 4 or later.")
        if mode not in self.supported_touch_policies:
            raise ValueError("Touch policy not available on this device.")
        self._put_data(key_slot.uif, struct.pack(">BB", mode, TOUCH_METHOD_BUTTON))

    def set_pin_retries(self, pw1_tries, pw2_tries, pw3_tries):
        """Requires Admin PIN verification."""
        if (1, 0, 0) <= self.version < (1, 0, 7):  # For YubiKey NEO
            raise ValueError(
                "Setting PIN retry counters requires version 1.0.7 or later."
            )
        if (4, 0, 0) <= self.version < (4, 3, 1):  # For YubiKey 4
            raise ValueError(
                "Setting PIN retry counters requires version 4.3.1 or later."
            )
        self._app.send_apdu(
            0,
            INS.SET_PIN_RETRIES,
            0,
            0,
            struct.pack(">BBB", pw1_tries, pw2_tries, pw3_tries),
        )

    def read_certificate(self, key_slot):
        require_version(self.version, (5, 2, 0))
        if key_slot == KEY_SLOT.ATT:
            data = self._get_data(DO.ATT_CERTIFICATE)
        else:
            self._select_certificate(key_slot)
            data = self._get_data(DO.CARDHOLDER_CERTIFICATE)
        if not data:
            raise ValueError("No certificate found!")
        return x509.load_der_x509_certificate(data, default_backend())

    def import_certificate(self, key_slot, certificate):
        """Requires Admin PIN verification."""
        require_version(self.version, (5, 2, 0))
        cert_data = certificate.public_bytes(Encoding.DER)
        if key_slot == KEY_SLOT.ATT:
            self._put_data(DO.ATT_CERTIFICATE, cert_data)
        else:
            self._select_certificate(key_slot)
            self._put_data(DO.CARDHOLDER_CERTIFICATE, cert_data)

    def import_key(self, key_slot, key, fingerprint=None, timestamp=None):
        """Requires Admin PIN verification."""
        if self.version >= (4, 0, 0):
            attributes = _get_key_attributes(key, key_slot)
            self._put_data(key_slot.key_id, attributes)

        template = _get_key_template(key, key_slot, self.version < (4, 0, 0))
        self._app.send_apdu(0, INS.PUT_DATA_ODD, 0x3F, 0xFF, template)

        if fingerprint is not None:
            self._put_data(key_slot.fingerprint, fingerprint)

        if timestamp is not None:
            self._put_data(key_slot.gen_time, struct.pack(">I", timestamp))

    def generate_rsa_key(self, key_slot, key_size, timestamp=None):
        """Requires Admin PIN verification."""
        if (4, 2, 0) <= self.version < (4, 3, 5):
            raise NotSupportedError("RSA key generation not supported on this YubiKey")

        if timestamp is None:
            timestamp = int(time.time())

        neo = self.version < (4, 0, 0)
        if not neo:
            attributes = _format_rsa_attributes(key_size)
            self._put_data(key_slot.key_id, attributes)
        elif key_size != 2048:
            raise ValueError("Unsupported key size!")
        resp = self._app.send_apdu(0, INS.GENERATE_ASYM, 0x80, 0x00, key_slot.crt)

        data = Tlv.parse_dict(Tlv.unpack(0x7F49, resp))
        numbers = rsa.RSAPublicNumbers(bytes2int(data[0x82]), bytes2int(data[0x81]))

        self._put_data(key_slot.gen_time, struct.pack(">I", timestamp))
        # TODO: Calculate and write fingerprint

        return numbers.public_key(default_backend())

    def generate_ec_key(self, key_slot, curve_name, timestamp=None):
        require_version(self.version, (5, 2, 0))
        """Requires Admin PIN verification."""
        if timestamp is None:
            timestamp = int(time.time())

        attributes = _format_ec_attributes(key_slot, curve_name)
        self._put_data(key_slot.key_id, attributes)
        resp = self._app.send_apdu(0, INS.GENERATE_ASYM, 0x80, 0x00, key_slot.crt)

        data = Tlv.parse_dict(Tlv.unpack(0x7F49, resp))
        pubkey_enc = data[0x86]

        self._put_data(key_slot.gen_time, struct.pack(">I", timestamp))
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
            self._put_data(key_slot.key_id, _format_rsa_attributes(4096))
            self._put_data(key_slot.key_id, _format_rsa_attributes(2048))

    def delete_certificate(self, key_slot):
        """Requires Admin PIN verification."""
        require_version(self.version, (5, 2, 0))
        if key_slot == KEY_SLOT.ATT:
            self._put_data(DO.ATT_CERTIFICATE, b"")
        else:
            self._select_certificate(key_slot)
            self._put_data(DO.CARDHOLDER_CERTIFICATE, b"")

    def attest(self, key_slot):
        """Requires User PIN verification."""
        require_version(self.version, (5, 2, 0))
        self._app.send_apdu(0x80, INS.GET_ATTESTATION, key_slot.index, 0)
        return self.read_certificate(key_slot)


def get_openpgp_info(controller: OpenPgpController) -> str:
    """Get human readable information about the OpenPGP configuration."""
    lines = []
    lines.append("OpenPGP version: %d.%d" % controller.get_openpgp_version())
    lines.append("Application version: %d.%d.%d" % controller.version)
    lines.append("")
    retries = controller.get_remaining_pin_tries()
    lines.append(f"PIN tries remaining: {retries.pin}")
    lines.append(f"Reset code tries remaining: {retries.reset}")
    lines.append(f"Admin PIN tries remaining: {retries.admin}")
    # Touch only available on YK4 and later
    if controller.version >= (4, 2, 6):
        lines.append("")
        lines.append("Touch policies")
        lines.append(f"Signature key           {controller.get_touch(KEY_SLOT.SIG)!s}")
        lines.append(f"Encryption key          {controller.get_touch(KEY_SLOT.ENC)!s}")
        lines.append(f"Authentication key      {controller.get_touch(KEY_SLOT.AUT)!s}")
        if controller.supports_attestation:
            lines.append(
                f"Attestation key         {controller.get_touch(KEY_SLOT.ATT)!s}"
            )

    return "\n".join(lines)
