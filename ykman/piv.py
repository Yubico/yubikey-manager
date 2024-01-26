# Copyright (c) 2017 Yubico AB
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


from yubikit.core import Tlv, BadResponseError, NotSupportedError
from yubikit.core.smartcard import ApduError, SW
from yubikit.piv import (
    PivSession,
    SLOT,
    OBJECT_ID,
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    ALGORITHM,
    TAG_LRC,
    SlotMetadata,
)

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime
import logging
import struct
import os
import re

from typing import Union, Mapping, Optional, List, Dict, Type, Any, cast


logger = logging.getLogger(__name__)


OBJECT_ID_PIVMAN_DATA = 0x5FFF00
OBJECT_ID_PIVMAN_PROTECTED_DATA = OBJECT_ID.PRINTED  # Use slot for printed information.


_NAME_ATTRIBUTES = {
    "CN": NameOID.COMMON_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "STREET": NameOID.STREET_ADDRESS,
    "DC": NameOID.DOMAIN_COMPONENT,
    "UID": NameOID.USER_ID,
}


_ESCAPED = "\\\"+,'<> #="


def _parse(value: str) -> List[List[str]]:
    remaining = list(value)
    name = []
    entry = []
    buf = ""
    hexbuf = b""
    while remaining:
        c = remaining.pop(0)
        if c == "\\":
            c1 = remaining.pop(0)
            if c1 in _ESCAPED:
                c = c1
            else:
                c2 = remaining.pop(0)
                hexbuf += bytes.fromhex(c1 + c2)
                try:
                    c = hexbuf.decode()
                    hexbuf = b""
                except UnicodeDecodeError:
                    continue  # Possibly multi-byte, expect more hex
        elif c in ",+":
            entry.append(buf)
            buf = ""
            if c == ",":
                name.append(entry)
                entry = []
            continue
        if hexbuf:
            raise ValueError("Invalid UTF-8 data")
        buf += c
    entry.append(buf)
    name.append(entry)
    return name


_DOTTED_STRING_RE = re.compile(r"\d(\.\d+)+")


def parse_rfc4514_string(value: str) -> x509.Name:
    """Parse an RFC 4514 string into a x509.Name.

    See: https://tools.ietf.org/html/rfc4514.html

    :param value: An RFC 4514 string.
    """
    name = _parse(value)
    attributes: List[x509.RelativeDistinguishedName] = []
    for entry in name:
        parts = []
        for part in entry:
            if "=" not in part:
                raise ValueError("Invalid RFC 4514 string")
            k, v = part.split("=", 1)
            if k in _NAME_ATTRIBUTES:
                attr = _NAME_ATTRIBUTES[k]
            elif _DOTTED_STRING_RE.fullmatch(k):
                attr = x509.ObjectIdentifier(k)
            else:
                raise ValueError(f"Unsupported attribute: '{k}'")
            parts.append(x509.NameAttribute(attr, v))
        attributes.insert(0, x509.RelativeDistinguishedName(parts))

    return x509.Name(attributes)


def _dummy_key(key_type):
    if key_type.algorithm == ALGORITHM.RSA:
        return rsa.generate_private_key(65537, key_type.bit_len, default_backend())
    if key_type == KEY_TYPE.ECCP256:
        return ec.generate_private_key(ec.SECP256R1(), default_backend())
    if key_type == KEY_TYPE.ECCP384:
        return ec.generate_private_key(ec.SECP384R1(), default_backend())
    if key_type == KEY_TYPE.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    if key_type == KEY_TYPE.X25519:
        return x25519.X25519PrivateKey.generate()
    raise ValueError("Invalid algorithm")


def derive_management_key(pin: str, salt: bytes) -> bytes:
    """Derive a management key from the users PIN and a salt.

    NOTE: This method of derivation is deprecated! Protect the management key using
    PivmanProtectedData instead.

    :param pin: The PIN.
    :param salt: The salt.
    """
    kdf = PBKDF2HMAC(hashes.SHA1(), 24, salt, 10000, default_backend())  # nosec
    return kdf.derive(pin.encode("utf-8"))


def generate_random_management_key(algorithm: MANAGEMENT_KEY_TYPE) -> bytes:
    """Generate a new random management key.

    :param algorithm: The algorithm for the management key.
    """
    return os.urandom(algorithm.key_len)


class PivmanData:
    def __init__(self, raw_data: bytes = Tlv(0x80)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self._flags = struct.unpack(">B", data[0x81])[0] if 0x81 in data else None
        self.salt = data.get(0x82)
        self.pin_timestamp = struct.unpack(">I", data[0x83]) if 0x83 in data else None

    def _get_flag(self, mask: int) -> bool:
        return bool((self._flags or 0) & mask)

    def _set_flag(self, mask: int, value: bool) -> None:
        if value:
            self._flags = (self._flags or 0) | mask
        elif self._flags is not None:
            self._flags &= ~mask

    @property
    def puk_blocked(self) -> bool:
        return self._get_flag(0x01)

    @puk_blocked.setter
    def puk_blocked(self, value: bool) -> None:
        self._set_flag(0x01, value)

    @property
    def mgm_key_protected(self) -> bool:
        return self._get_flag(0x02)

    @mgm_key_protected.setter
    def mgm_key_protected(self, value: bool) -> None:
        self._set_flag(0x02, value)

    @property
    def has_protected_key(self) -> bool:
        return self.has_derived_key or self.has_stored_key

    @property
    def has_derived_key(self) -> bool:
        return self.salt is not None

    @property
    def has_stored_key(self) -> bool:
        return self.mgm_key_protected

    def get_bytes(self) -> bytes:
        data = b""
        if self._flags:
            data += Tlv(0x81, struct.pack(">B", self._flags))
        if self.salt is not None:
            data += Tlv(0x82, self.salt)
        if self.pin_timestamp is not None:
            data += Tlv(0x83, struct.pack(">I", self.pin_timestamp))
        return Tlv(0x80, data)


class PivmanProtectedData:
    def __init__(self, raw_data: bytes = Tlv(0x88)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self.key = data.get(0x89)

    def get_bytes(self) -> bytes:
        data = b""
        if self.key is not None:
            data += Tlv(0x89, self.key)
        return Tlv(0x88, data)


def get_pivman_data(session: PivSession) -> PivmanData:
    """Read out the Pivman data from a YubiKey.

    :param session: The PIV session.
    """
    logger.debug("Reading pivman data")
    try:
        return PivmanData(session.get_object(OBJECT_ID_PIVMAN_DATA))
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            # No data there, initialise a new object.
            logger.debug("No data, initializing blank")
            return PivmanData()
        raise


def get_pivman_protected_data(session: PivSession) -> PivmanProtectedData:
    """Read out the Pivman protected data from a YubiKey.

    This function requires PIN verification prior to being called.

    :param session: The PIV session.
    """
    logger.debug("Reading protected pivman data")
    try:
        return PivmanProtectedData(session.get_object(OBJECT_ID_PIVMAN_PROTECTED_DATA))
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            # No data there, initialise a new object.
            logger.debug("No data, initializing blank")
            return PivmanProtectedData()
        raise


def pivman_set_mgm_key(
    session: PivSession,
    new_key: bytes,
    algorithm: MANAGEMENT_KEY_TYPE,
    touch: bool = False,
    store_on_device: bool = False,
) -> None:
    """Set a new management key, while keeping PivmanData in sync.

    :param session: The PIV session.
    :param new_key: The new management key.
    :param algorithm: The algorithm for the management key.
    :param touch: If set, touch is required.
    :param store_on_device: If set, the management key is stored on device.
    """
    pivman = get_pivman_data(session)
    pivman_prot = None

    if store_on_device or (not store_on_device and pivman.has_stored_key):
        # Ensure we have access to protected data before overwriting key
        try:
            pivman_prot = get_pivman_protected_data(session)
        except Exception:
            logger.debug("Failed to initialize protected pivman data", exc_info=True)
            if store_on_device:
                raise

    # Set the new management key
    session.set_management_key(algorithm, new_key, touch)

    if pivman.has_derived_key:
        # Clear salt for old derived keys.
        logger.debug("Clearing salt in pivman data")
        pivman.salt = None

    # Set flag for stored or not stored key.
    pivman.mgm_key_protected = store_on_device

    # Update readable pivman data
    session.put_object(OBJECT_ID_PIVMAN_DATA, pivman.get_bytes())

    if pivman_prot is not None:
        if store_on_device:
            # Store key in protected pivman data
            logger.debug("Storing key in protected pivman data")
            pivman_prot.key = new_key
            session.put_object(OBJECT_ID_PIVMAN_PROTECTED_DATA, pivman_prot.get_bytes())
        elif pivman_prot.key:
            # If new key should not be stored and there is an old stored key,
            # try to clear it.
            logger.debug("Clearing old key in protected pivman data")
            try:
                pivman_prot.key = None
                session.put_object(
                    OBJECT_ID_PIVMAN_PROTECTED_DATA,
                    pivman_prot.get_bytes(),
                )
            except ApduError:
                logger.debug("No PIN provided, can't clear key...", exc_info=True)


def pivman_change_pin(session: PivSession, old_pin: str, new_pin: str) -> None:
    """Change the PIN, while keeping PivmanData in sync.

    :param session: The PIV session.
    :param old_pin: The old PIN.
    :param new_pin: The new PIN.
    """
    session.change_pin(old_pin, new_pin)

    pivman = get_pivman_data(session)
    if pivman.has_derived_key:
        logger.debug("Has derived management key, update for new PIN")
        session.authenticate(
            MANAGEMENT_KEY_TYPE.TDES,
            derive_management_key(old_pin, cast(bytes, pivman.salt)),
        )
        session.verify_pin(new_pin)
        new_salt = os.urandom(16)
        new_key = derive_management_key(new_pin, new_salt)
        session.set_management_key(MANAGEMENT_KEY_TYPE.TDES, new_key)
        pivman.salt = new_salt
        session.put_object(OBJECT_ID_PIVMAN_DATA, pivman.get_bytes())


def pivman_set_pin_attempts(
    session: PivSession, pin_attempts: int, puk_attempts: int
) -> None:
    """Set the number of PIN and PUK retry attempts, while keeping PivmanData in sync.

    :param session: The PIV session.
    :param pin_attempts: The PIN attempts.
    :param puk_attempts: The PUK attempts.
    """
    session.set_pin_attempts(pin_attempts, puk_attempts)
    pivman = get_pivman_data(session)
    if pivman.puk_blocked:
        pivman.puk_blocked = False
        session.put_object(OBJECT_ID_PIVMAN_DATA, pivman.get_bytes())


def list_certificates(session: PivSession) -> Mapping[SLOT, Optional[x509.Certificate]]:
    """Read out and parse stored certificates.

    Only certificates which are successfully parsed are returned.

    :param session: The PIV session.
    """
    certs = {}
    for slot in set(SLOT) - {SLOT.ATTESTATION}:
        try:
            certs[slot] = session.get_certificate(slot)
        except ApduError:
            pass
        except BadResponseError:
            certs[slot] = None

    return certs


def _list_keys(session: PivSession) -> Mapping[SLOT, SlotMetadata]:
    keys = {}
    for slot in set(SLOT) - {SLOT.ATTESTATION}:
        try:
            keys[slot] = session.get_slot_metadata(slot)
        except ApduError as e:
            if e.sw != SW.REFERENCE_DATA_NOT_FOUND:
                raise
    return keys


def check_key(
    session: PivSession,
    slot: SLOT,
    public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
) -> bool:
    """Check that a given public key corresponds to the private key in a slot.

    This will create a signature using the private key, so the PIN must be verified
    prior to calling this function if the PIN policy requires it.

    :param session: The PIV session.
    :param slot: The slot.
    :param public_key: The public key.
    """
    try:
        test_data = b"test"
        logger.debug(
            "Testing private key by creating a test signature, and verifying it"
        )

        test_sig = session.sign(
            slot,
            KEY_TYPE.from_public_key(public_key),
            test_data,
            hashes.SHA256(),
            padding.PKCS1v15(),  # Only used for RSA
        )

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                test_sig,
                test_data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(test_sig, test_data, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError("Unknown key type: " + type(public_key))
        return True

    except ApduError as e:
        if e.sw in (SW.INCORRECT_PARAMETERS, SW.WRONG_PARAMETERS_P1P2):
            logger.debug(f"Couldn't create signature: SW={e.sw:04x}")
            return False
        raise

    except InvalidSignature:
        logger.debug("Signature verification failed")
        return False


def generate_chuid() -> bytes:
    """Generate a CHUID (Cardholder Unique Identifier)."""
    # Non-Federal Issuer FASC-N
    # [9999-9999-999999-0-1-0000000000300001]
    FASC_N = (
        b"\xd4\xe7\x39\xda\x73\x9c\xed\x39\xce\x73\x9d\x83\x68"
        + b"\x58\x21\x08\x42\x10\x84\x21\xc8\x42\x10\xc3\xeb"
    )
    # Expires on: 2030-01-01
    EXPIRY = b"\x32\x30\x33\x30\x30\x31\x30\x31"

    return (
        Tlv(0x30, FASC_N)
        + Tlv(0x34, os.urandom(16))
        + Tlv(0x35, EXPIRY)
        + Tlv(0x3E)
        + Tlv(TAG_LRC)
    )


def generate_ccc() -> bytes:
    """Generate a CCC (Card Capability Container)."""
    return (
        Tlv(0xF0, b"\xa0\x00\x00\x01\x16\xff\x02" + os.urandom(14))
        + Tlv(0xF1, b"\x21")
        + Tlv(0xF2, b"\x21")
        + Tlv(0xF3)
        + Tlv(0xF4, b"\x00")
        + Tlv(0xF5, b"\x10")
        + Tlv(0xF6)
        + Tlv(0xF7)
        + Tlv(0xFA)
        + Tlv(0xFB)
        + Tlv(0xFC)
        + Tlv(0xFD)
        + Tlv(TAG_LRC)
    )


def get_piv_info(session: PivSession):
    """Get human readable information about the PIV configuration.

    :param session: The PIV session.
    """
    pivman = get_pivman_data(session)
    info: Dict[str, Any] = {
        "PIV version": session.version,
    }
    lines: List[Any] = [info]

    try:
        pin_data = session.get_pin_metadata()
        if pin_data.default_value:
            lines.append("WARNING: Using default PIN!")
        tries_str = "%d/%d" % (pin_data.attempts_remaining, pin_data.total_attempts)
    except NotSupportedError:
        # Largest possible number of PIN tries to get back is 15
        tries = session.get_pin_attempts()
        tries_str = "15 or more" if tries == 15 else str(tries)
    info["PIN tries remaining"] = tries_str
    try:
        puk_data = session.get_puk_metadata()
        if puk_data.attempts_remaining == 0:
            lines.append("PUK is blocked")
        elif puk_data.default_value:
            lines.append("WARNING: Using default PUK!")
        tries_str = "%d/%d" % (
            puk_data.attempts_remaining,
            puk_data.total_attempts,
        )
        info["PUK tries remaining"] = tries_str
    except NotSupportedError:
        if pivman.puk_blocked:
            lines.append("PUK is blocked")

    try:
        bio = session.get_bio_metadata()
        if bio.configured:
            info[
                "Biometrics"
            ] = f"Configured, {bio.attempts_remaining} attempts remaining"
        else:
            info["Biometrics"] = "Not configured"
    except NotSupportedError:
        pass

    try:
        metadata = session.get_management_key_metadata()
        if metadata.default_value:
            lines.append("WARNING: Using default Management key!")
        key_type = metadata.key_type
    except NotSupportedError:
        key_type = MANAGEMENT_KEY_TYPE.TDES
    info["Management key algorithm"] = key_type.name

    if pivman.has_derived_key:
        lines.append("Management key is derived from PIN.")
    if pivman.has_stored_key:
        lines.append("Management key is stored on the YubiKey, protected by PIN.")

    objects: Dict[str, Any] = {}
    lines.append(objects)
    try:
        objects["CHUID"] = session.get_object(OBJECT_ID.CHUID)
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            objects["CHUID"] = "No data available"

    try:
        objects["CCC"] = session.get_object(OBJECT_ID.CAPABILITY)
    except ApduError as e:
        if e.sw == SW.FILE_NOT_FOUND:
            objects["CCC"] = "No data available"

    certs = list_certificates(session)
    try:
        keys = _list_keys(session)
    except NotSupportedError:
        keys = {}
    for slot in set(SLOT) - {SLOT.ATTESTATION}:
        if slot not in keys and slot not in certs:
            continue

        cert_data: Dict[str, Any] = {}
        objects[f"Slot {slot}"] = cert_data
        if slot in keys:
            cert_data["Private key type"] = keys[slot].key_type
        else:
            cert_data["Private key type"] = "EMPTY"
        cert = certs.get(slot, None)
        if cert:
            try:
                # Try to read out full DN, fallback to only CN.
                # Support for DN was added in crytography 2.5
                subject_dn = cert.subject.rfc4514_string()
                issuer_dn = cert.issuer.rfc4514_string()
                print_dn = True
            except AttributeError:
                print_dn = False
                logger.debug("Failed to read DN, falling back to only CNs")
                cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                subject_cn = cn[0].value if cn else "None"
                cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                issuer_cn = cn[0].value if cn else "None"
            except ValueError as e:
                # Malformed certificates may throw ValueError
                logger.debug("Failed parsing certificate", exc_info=True)
                cert_data["Error"] = f"Malformed certificate: {e}"
                continue

            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            try:
                key_algo = KEY_TYPE.from_public_key(cert.public_key()).name
            except ValueError:
                key_algo = "Unsupported"
            serial = cert.serial_number
            try:
                try:  # Prefer timezone-aware variant (cryptography >= 42)
                    not_before: Optional[datetime] = cert.not_valid_before_utc
                except AttributeError:
                    not_before = cert.not_valid_before
            except ValueError:
                logger.debug("Failed reading not_valid_before", exc_info=True)
                not_before = None
            try:
                try:  # Prefer timezone-aware variant (cryptography >= 42)
                    not_after: Optional[datetime] = cert.not_valid_after_utc
                except AttributeError:
                    not_after = cert.not_valid_after
            except ValueError:
                logger.debug("Failed reading not_valid_after", exc_info=True)
                not_after = None

            # Print out everything
            cert_data["Public key type"] = key_algo
            if print_dn:
                cert_data["Subject DN"] = subject_dn
                cert_data["Issuer DN"] = issuer_dn
            else:
                cert_data["Subject CN"] = subject_cn
                cert_data["Issuer CN"] = issuer_cn
            cert_data["Serial"] = serial
            cert_data["Fingerprint"] = fingerprint
            if not_before:
                cert_data["Not before"] = not_before.isoformat()
            if not_after:
                cert_data["Not after"] = not_after.isoformat()
        elif slot in certs:
            cert_data["Error"] = "Failed to parse certificate"

    return lines


_AllowedHashTypes = Union[
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512,
]


def _hash(key_type, hash_algorithm):
    if key_type in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
        return None
    return hash_algorithm()


def sign_certificate_builder(
    session: PivSession,
    slot: SLOT,
    key_type: KEY_TYPE,
    builder: x509.CertificateBuilder,
    hash_algorithm: Type[_AllowedHashTypes] = hashes.SHA256,
) -> x509.Certificate:
    """Sign a Certificate.

    :param session: The PIV session.
    :param slot: The slot.
    :param key_type: The key type.
    :param builder: The x509 certificate builder object.
    :param hash_algorithm: The hash algorithm, ignored for Curve 25519.
    """
    logger.debug("Signing a certificate")
    dummy_key = _dummy_key(key_type)
    cert = builder.sign(dummy_key, _hash(key_type, hash_algorithm), default_backend())

    sig = session.sign(
        slot,
        key_type,
        cert.tbs_certificate_bytes,
        _hash(key_type, hash_algorithm),
        padding.PKCS1v15(),  # Only used for RSA
    )

    seq = Tlv.parse_list(Tlv.unpack(0x30, cert.public_bytes(Encoding.DER)))
    # Replace signature, add unused bits = 0
    seq[2] = Tlv(seq[2].tag, b"\0" + sig)
    # Re-assemble sequence
    der = Tlv(0x30, b"".join(seq))

    return x509.load_der_x509_certificate(der, default_backend())


def sign_csr_builder(
    session: PivSession,
    slot: SLOT,
    public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    builder: x509.CertificateSigningRequestBuilder,
    hash_algorithm: Type[_AllowedHashTypes] = hashes.SHA256,
) -> x509.CertificateSigningRequest:
    """Sign a CSR.

    :param session: The PIV session.
    :param slot: The slot.
    :param public_key: The public key.
    :param builder: The x509 certificate signing request builder
        object.
    :param hash_algorithm: The hash algorithm, ignored for Curve 25519.
    """
    logger.debug("Signing a CSR")
    key_type = KEY_TYPE.from_public_key(public_key)
    dummy_key = _dummy_key(key_type)

    csr = builder.sign(dummy_key, _hash(key_type, hash_algorithm), default_backend())
    seq = Tlv.parse_list(Tlv.unpack(0x30, csr.public_bytes(Encoding.DER)))

    # Replace public key
    pub_format = (
        PublicFormat.PKCS1
        if key_type.algorithm == ALGORITHM.RSA
        else PublicFormat.SubjectPublicKeyInfo
    )
    dummy_bytes = dummy_key.public_key().public_bytes(Encoding.DER, pub_format)
    pub_bytes = public_key.public_bytes(Encoding.DER, pub_format)
    seq[0] = Tlv(seq[0].replace(dummy_bytes, pub_bytes))

    sig = session.sign(
        slot,
        key_type,
        seq[0],
        _hash(key_type, hash_algorithm),
        padding.PKCS1v15(),  # Only used for RSA
    )

    # Replace signature, add unused bits = 0
    seq[2] = Tlv(seq[2].tag, b"\0" + sig)
    # Re-assemble sequence
    der = Tlv(0x30, b"".join(seq))

    return x509.load_der_x509_csr(der, default_backend())


def generate_self_signed_certificate(
    session: PivSession,
    slot: SLOT,
    public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    subject_str: str,
    valid_from: datetime,
    valid_to: datetime,
    hash_algorithm: Type[_AllowedHashTypes] = hashes.SHA256,
) -> x509.Certificate:
    """Generate a self-signed certificate using a private key in a slot.

    :param session: The PIV session.
    :param slot: The slot.
    :param public_key: The public key.
    :param subject_str: The subject RFC 4514 string.
    :param valid_from: The date from when the certificate is valid.
    :param valid_to: The date when the certificate expires.
    :param hash_algorithm: The hash algorithm.
    """
    logger.debug("Generating a self-signed certificate")
    key_type = KEY_TYPE.from_public_key(public_key)

    subject = parse_rfc4514_string(subject_str)
    builder = (
        x509.CertificateBuilder()
        .public_key(public_key)
        .subject_name(subject)
        .issuer_name(subject)  # Same as subject on self-signed certificate.
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
    )

    return sign_certificate_builder(session, slot, key_type, builder, hash_algorithm)


def generate_csr(
    session: PivSession,
    slot: SLOT,
    public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    subject_str: str,
    hash_algorithm: Type[_AllowedHashTypes] = hashes.SHA256,
) -> x509.CertificateSigningRequest:
    """Generate a CSR using a private key in a slot.

    :param session: The PIV session.
    :param slot: The slot.
    :param public_key: The public key.
    :param subject_str: The subject RFC 4514 string.
    :param hash_algorithm: The hash algorithm.
    """
    logger.debug("Generating a CSR")
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        parse_rfc4514_string(subject_str)
    )

    return sign_csr_builder(session, slot, public_key, builder, hash_algorithm)
