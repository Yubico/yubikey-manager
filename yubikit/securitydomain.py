from __future__ import annotations

import logging
from enum import IntEnum, unique
from typing import Mapping, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .core import (
    BadResponseError,
    NotSupportedError,
    Version,
    _override_version,
    int2bytes,
)
from .core.smartcard import (
    SW,
    ApduError,
    SmartCardConnection,
    SmartCardProtocol,
)
from .core.smartcard.scp import (
    KeyRef,
    Scp03KeyParams,
    ScpKeyParams,
    StaticKeys,
)

try:
    from _ykman_native.sessions import (
        SecurityDomainSession as _NativeSecurityDomainSession,
    )
except ImportError:
    _NativeSecurityDomainSession = None

logger = logging.getLogger(__name__)


@unique
class Curve(IntEnum):
    SECP256R1 = 0x00
    SECP384R1 = 0x01
    SECP521R1 = 0x02
    BrainpoolP256R1 = 0x03
    BrainpoolP384R1 = 0x05
    BrainpoolP512R1 = 0x07

    @classmethod
    def _from_key(
        cls, key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey
    ) -> Curve:
        name = key.curve.name.lower()
        for curve in cls:
            if curve.name.lower() == name:
                return curve
        raise ValueError("Unsupported private key")

    @property
    def _curve(self) -> ec.EllipticCurve:
        return getattr(ec, self.name)()


class SecurityDomainSession:
    """A session for managing SCP keys.

    Delegates to the Rust SecurityDomainSession implementation via PyO3.
    Falls back to Python for SCP-encrypted sessions.
    """

    def __init__(self, connection: SmartCardConnection):
        if _NativeSecurityDomainSession is None:
            raise RuntimeError("Native security domain session not available")
        native = _NativeSecurityDomainSession(connection)
        self._native = native
        self._version = _override_version.patch(Version(*native.version))
        if self._version != Version(*native.version):
            native.version = tuple(self._version)
        self.protocol = SmartCardProtocol(connection)
        self.protocol.configure(self._version)
        self._authenticated = False
        self._dek: bytes | None = None
        logger.debug("SecurityDomain session initialized")

    def authenticate(self, key_params: ScpKeyParams) -> None:
        """Initialize SCP and authenticate the session.

        SCP11b does not authenticate the OCE, and will not allow the usage of commands
        which require authentication of the OCE.
        """
        try:
            self._native.authenticate(key_params)
        except ApduError as e:
            if e.sw == SW.CLASS_NOT_SUPPORTED:
                raise NotSupportedError(
                    "This YubiKey does not support secure messaging"
                )
            if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
                raise ValueError("Incorrect SCP parameters")
            raise
        except BadResponseError as e:
            if "receipt" in str(e).lower():
                raise InvalidSignature(str(e))
            raise ValueError("Incorrect SCP parameters")
        # Store DEK for put_key operations
        if isinstance(key_params, Scp03KeyParams):
            self._dek = key_params.keys.key_dek
        else:
            self._dek = None
        self._authenticated = True

    def get_data(self, tag: int, data: bytes = b"") -> bytes:
        """Read data from the security domain."""
        return bytes(self._native.get_data(tag, data))

    def get_key_information(self) -> Mapping[KeyRef, Mapping[int, int]]:
        """Get information about the currently loaded keys."""
        raw = self._native.get_key_information()
        return {KeyRef(kid, kvn): dict(v) for (kid, kvn), v in raw.items()}

    def get_card_recognition_data(self) -> bytes:
        """Get information about the card."""
        return bytes(self._native.get_card_recognition_data())

    def get_supported_ca_identifiers(
        self, kloc: bool = False, klcc: bool = False
    ) -> Mapping[KeyRef, bytes]:
        """Get a list of the CA issuer Subject Key Identifiers for keys.

        Setting one of kloc or klcc to True will cause only those CAs to be returned.
        By default, this will get both KLOC and KLCC CAs.

        :param kloc: Get KLOC CAs.
        :param klcc: Get KLCC CAs.
        """
        raw = self._native.get_supported_ca_identifiers(kloc, klcc)
        return {KeyRef(kid, kvn): bytes(v) for (kid, kvn), v in raw.items()}

    def get_certificate_bundle(self, key: KeyRef) -> Sequence[x509.Certificate]:
        """Get the certificates associated with the given SCP11 private key.

        Certificates are returned leaf-last.
        """
        logger.debug(f"Getting certificate bundle for {key}")
        return [
            x509.load_der_x509_certificate(der)
            for der in self._native.get_certificate_bundle(key.kid, key.kvn)
        ]

    def reset(self) -> None:
        """Perform a factory reset of the Security Domain.

        This will remove all keys and associated data, as well as restore the default
        SCP03 static keys, and generate a new (attestable) SCP11b key.
        """
        logger.debug("Resetting all SCP keys")
        self._native.reset()
        logger.info("SCP keys reset")

    def store_data(self, data: bytes) -> None:
        """Stores data in the security domain.

        Requires OCE verification.
        """
        self._native.store_data(data)

    def store_certificate_bundle(
        self, key: KeyRef, certificates: Sequence[x509.Certificate]
    ) -> None:
        """Store the certificate chain for the given key.

        Requires OCE verification.

        Certificates should be in order, with the leaf certificate last.
        """
        logger.debug(f"Storing certificate bundle for {key}")
        der_certs = [c.public_bytes(serialization.Encoding.DER) for c in certificates]
        self._native.store_certificate_bundle(key.kid, key.kvn, der_certs)
        logger.info("Certificate bundle stored")

    def store_allowlist(self, key: KeyRef, serials: Sequence[int]) -> None:
        """Store which certificate serial numbers that can be used for a given key.

        Requires OCE verification.

        If no allowlist is stored, any certificate signed by the CA can be used.
        """
        logger.debug(f"Storing serial allowlist for {key}")
        serial_bytes = [
            s.to_bytes((s.bit_length() + 7) // 8, "big") if s > 0 else b"\x00"
            for s in serials
        ]
        self._native.store_allowlist(key.kid, key.kvn, serial_bytes)
        logger.info("Serial allowlist stored")

    def store_ca_issuer(self, key: KeyRef, ski: bytes) -> None:
        """Store the SKI (Subject Key Identifier) for the CA of a given key.

        Requires OCE verification.
        """
        logger.debug(f"Storing CA issuer SKI for {key}: {ski.hex()}")
        self._native.store_ca_issuer(key.kid, key.kvn, ski)
        logger.info("CA issuer SKI stored")

    def delete_key(self, kid: int = 0, kvn: int = 0, delete_last: bool = False) -> None:
        """Delete one (or more) keys.

        Requires OCE verification.

        All keys matching the given KID and/or KVN will be deleted.
        To delete the final key you must set delete_last = True.
        """
        if not kid and not kvn:
            raise ValueError("Must specify at least one of kid, kvn.")

        if kid in (1, 2, 3):
            if kvn:
                kid = 0
            else:
                raise ValueError("SCP03 keys can only be deleted by KVN")
        logger.debug(f"Deleting keys with KID={kid or 'ANY'}, KVN={kvn or 'ANY'}")
        self._native.delete_key(kid, kvn, delete_last)
        logger.info("Keys deleted")

    def generate_ec_key(
        self, key: KeyRef, curve: Curve = Curve.SECP256R1, replace_kvn: int = 0
    ) -> ec.EllipticCurvePublicKey:
        """Generate a new SCP11 key.

        Requires OCE verification.

        Use replace_kvn to replace an existing key.
        """
        logger.debug(
            f"Generating new key for {key}"
            + (f", replacing KVN={replace_kvn}" if replace_kvn else "")
        )
        encoded_point = bytes(
            self._native.generate_ec_key(key.kid, key.kvn, int(curve), replace_kvn)
        )
        logger.info("New key generated")
        return ec.EllipticCurvePublicKey.from_encoded_point(curve._curve, encoded_point)

    def put_key(
        self,
        key: KeyRef,
        sk: StaticKeys | ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey,
        replace_kvn: int = 0,
    ) -> None:
        """Import an SCP key.

        Requires OCE verification.

        The value of the sk argument should match the SCP type as defined by the KID.
        Use replace_kvn to replace an existing key.
        """
        logger.debug(f"Importing key into {key} of type {type(sk)}")
        if not self._authenticated:
            raise ValueError("Must be authenticated!")

        if isinstance(sk, StaticKeys):
            if not self._dek:
                raise ValueError("No session DEK key available")
            if not sk.key_dek:
                raise ValueError("New DEK must be set in static keys")
            self._native.put_key_static(
                key.kid,
                key.kvn,
                sk.key_enc,
                sk.key_mac,
                sk.key_dek,
                self._dek,
                replace_kvn,
            )
        elif isinstance(sk, ec.EllipticCurvePrivateKey):
            if not self._dek:
                raise ValueError("No session DEK key available")
            n = (sk.key_size + 7) // 8
            s = int2bytes(sk.private_numbers().private_value, n)
            curve_val = Curve._from_key(sk)
            self._native.put_key_ec_private(
                key.kid, key.kvn, s, int(curve_val), self._dek, replace_kvn
            )
        elif isinstance(sk, ec.EllipticCurvePublicKey):
            pk_bytes = sk.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            curve_val = Curve._from_key(sk)
            self._native.put_key_ec_public(
                key.kid, key.kvn, pk_bytes, int(curve_val), replace_kvn
            )
        else:
            raise TypeError("Unsupported key type")
        logger.info("Key imported")
