from yubikit.openpgp import (
    OpenPgpSession,
    KEY_REF,
    OpenPgpAid,
    RSA_SIZE,
    OID,
    PW,
    RsaAttributes,
    EcAttributes,
)
from yubikit.core.smartcard import ApduError, SW
from yubikit.core import NotSupportedError

from pgpy import PGPKey
from pgpy.constants import PubKeyAlgorithm, ECPointFormat, EllipticCurveOID
from pgpy.packet.packets import PrivKeyV4, PrivSubKeyV4, PubKeyV4, PubSubKeyV4
from pgpy.packet.fields import String2Key, String2KeyType, S2KGNUExtension, ECPoint
from pgpy.packet.types import MPI
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der.encoder import encode
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest import mock
from functools import wraps
import copy
import weakref
from typing import Optional, cast
import logging

logger = logging.getLogger(__name__)


def _serial_for_aid(aid: bytes) -> bytearray:
    serial = bytearray(aid)
    serial[6:8] = b"\0\0"  # Version number is zeroed out
    return serial


def _stub_s2k(aid: Optional[OpenPgpAid] = None):
    s2k = String2Key()
    s2k.usage = 0xFF
    s2k.specifier = String2KeyType.GNUExtension
    s2k.gnuext = S2KGNUExtension.Smartcard if aid else S2KGNUExtension.NoSecret
    if aid:
        s2k.scserial = _serial_for_aid(aid)
    return s2k


def _make_stub(key: PGPKey, s2k: String2Key):
    key._key.keymaterial.clear()
    key._key.keymaterial.s2k = s2k
    key._key.update_hlen()


def key_from_card(session: OpenPgpSession, key_ref: KEY_REF) -> PGPKey:
    """Reads a public key already stored on the YubiKey as a PGPKey.

    The returned PGPKey will be a private key with stubbed key material, redirecting to
    the YubiKey.
    """
    pub = session.get_public_key(key_ref)
    attributes = session.get_algorithm_attributes(key_ref)
    pk = PrivKeyV4()

    created = session.get_generation_times().get(key_ref)
    if created:
        pk.created = datetime.fromtimestamp(created, timezone.utc)

    if isinstance(attributes, RsaAttributes):
        pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        rsa_num = cast(RSAPublicKey, pub).public_numbers()
        pk.keymaterial.n = MPI(rsa_num.n)
        pk.keymaterial.e = MPI(rsa_num.e)
    elif isinstance(attributes, EcAttributes):
        if key_ref == KEY_REF.DEC:
            pk.pkalg = PubKeyAlgorithm.ECDH
        elif attributes.algorithm_id == 0x16:
            pk.pkalg = PubKeyAlgorithm.EdDSA
        else:
            pk.pkalg = PubKeyAlgorithm.ECDSA
        for oid in EllipticCurveOID:
            if oid.value and OID(encode(oid.value)[2:]) == attributes.oid:
                break
        else:
            raise ValueError("Unsupported OID")

        pk.keymaterial.oid = oid
        if oid in {EllipticCurveOID.Ed25519, EllipticCurveOID.Curve25519}:
            pk.keymaterial.p = ECPoint.from_values(
                oid.key_size,
                ECPointFormat.Native,
                pub.public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
        else:
            ec_num = cast(EllipticCurvePublicKey, pub).public_numbers()
            pk.keymaterial.p = ECPoint.from_values(
                oid.key_size, ECPointFormat.Standard, MPI(ec_num.x), MPI(ec_num.y)
            )
        if pk.pkalg == PubKeyAlgorithm.ECDH:
            pk.keymaterial.kdf.halg = oid.kdf_halg
            pk.keymaterial.kdf.encalg = oid.kek_alg

    pk.keymaterial.s2k = _stub_s2k(session.aid)
    pk.update_hlen()

    key = PGPKey()
    key._key = pk
    bind_key(session, key)
    return key


def generate_key(
    session: OpenPgpSession,
    key_ref: KEY_REF,
    key_algorithm: PubKeyAlgorithm,
    key_size,
    created: Optional[datetime] = None,
) -> PGPKey:
    """Generates a new PGPKey on the YubiKey in the given key slot.

    This will generate a new PGPKey of the given type on the YubiKey and return it.
    The private key portion will redirect to the YubiKey, making it usable with the
    unlock_key function.
    """
    pk = PrivKeyV4()
    pk.pkalg = key_algorithm
    if created is not None:
        pk.created = created

    if key_algorithm in {
        PubKeyAlgorithm.RSAEncryptOrSign,
        PubKeyAlgorithm.RSAEncrypt,
        PubKeyAlgorithm.RSASign,
    }:
        rsa_pub = session.generate_rsa_key(key_ref, RSA_SIZE(key_size))
        rsa_num = rsa_pub.public_numbers()
        pk.keymaterial.n = MPI(rsa_num.n)
        pk.keymaterial.e = MPI(rsa_num.e)
    elif key_algorithm in {
        PubKeyAlgorithm.ECDH,
        PubKeyAlgorithm.ECDSA,
        PubKeyAlgorithm.EdDSA,
    }:
        oid = key_size
        ec_pub = session.generate_ec_key(key_ref, OID(encode(oid.value)[2:]))
        pk.keymaterial.oid = oid
        if oid in {EllipticCurveOID.Ed25519, EllipticCurveOID.Curve25519}:
            pk.keymaterial.p = ECPoint.from_values(
                oid.key_size,
                ECPointFormat.Native,
                ec_pub.public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
        else:
            ec_num = cast(EllipticCurvePublicKey, ec_pub).public_numbers()
            pk.keymaterial.p = ECPoint.from_values(
                oid.key_size, ECPointFormat.Standard, MPI(ec_num.x), MPI(ec_num.y)
            )
        if key_algorithm == PubKeyAlgorithm.ECDH:
            pk.keymaterial.kdf.halg = oid.kdf_halg
            pk.keymaterial.kdf.encalg = oid.kek_alg

    pk.keymaterial.s2k = _stub_s2k(session.aid)
    pk.update_hlen()

    session.set_fingerprint(key_ref, bytes(pk.fingerprint))
    session.set_generation_time(key_ref, int(pk.created.timestamp()))

    key = PGPKey()
    key._key = pk

    return key


def key_to_card(session: OpenPgpSession, key_ref: KEY_REF, key: PGPKey) -> None:
    """Moves the private key material from a PGPKey to the YubiKey.

    This operation modifies the given key, replacing its private key material
    with a reference to the key on card.
    """
    session.put_key(key_ref, key.__key__.__privkey__())
    session.set_fingerprint(key_ref, bytes(key.fingerprint))
    session.set_generation_time(key_ref, int(key.created.timestamp()))
    _make_stub(key, _stub_s2k(session.aid))


def _make_private_copy(pub: PubKeyV4, s2k: String2Key) -> PrivKeyV4:
    priv = PrivKeyV4() if not isinstance(pub, PubSubKeyV4) else PrivSubKeyV4()
    priv.created = pub.created
    priv.pkalg = pub.pkalg

    for pm in pub.keymaterial.__pubfields__:
        setattr(priv.keymaterial, pm, copy.copy(getattr(pub.keymaterial, pm)))

    if pub.pkalg in {PubKeyAlgorithm.ECDSA, PubKeyAlgorithm.EdDSA}:
        priv.keymaterial.oid = pub.keymaterial.oid
    elif pub.pkalg == PubKeyAlgorithm.ECDH:
        priv.keymaterial.oid = pub.keymaterial.oid
        priv.keymaterial.kdf = copy.copy(pub.keymaterial.kdf)

    priv.keymaterial.s2k = s2k
    priv.update_hlen()

    return priv


def stub_private_key(pub: PGPKey) -> PGPKey:
    """Creates a private PGPKey from a public one, without private key material.

    The stubs can be bound to redirect to a YubiKey using the bind_key function.
    """
    if not pub.is_public:
        raise ValueError("Must be called with public key")

    priv = PGPKey()
    priv.ascii_headers = pub.ascii_headers.copy()

    s2k = _stub_s2k()

    priv |= _make_private_copy(pub._key, s2k)

    for skid, subkey in pub.subkeys.items():
        priv |= stub_private_key(subkey)

    for uid in pub._uids:
        priv |= copy.copy(uid)

    for sig in pub._signatures:
        if sig.parent is None:
            priv |= copy.copy(sig)

    priv._sibling = weakref.ref(pub)
    pub._sibling = weakref.ref(priv)

    if pub.parent:
        priv._parent = weakref.ref(pub.parent)

    return priv


def bind_key(session: OpenPgpSession, key: PGPKey) -> None:
    """Binds empty private key stubs to redirect to slots on the YubiKey.

    Replaces any key material of the key with a pointer to a key on the YubiKey if such
    a subkey exists (identified by fingerprint).
    """
    if key.is_public:
        raise ValueError("Must be called with private key")

    data = session.get_application_related_data()
    fingerprints = set(data.discretionary.fingerprints.values())
    s2k = _stub_s2k(session.aid)

    keys = [key] + list(key.subkeys.values())
    for sk in keys:
        if bytes(sk.fingerprint) in fingerprints:
            _make_stub(sk, s2k)

    return key


class _SessionWrapper:
    def __init__(self, session, pin):
        self._session = session
        self._pin = pin
        self._unlocked = False

    def clear(self):
        del self._pin
        if self._unlocked:
            try:
                self._session.unverify_pin(PW.USER)
            except NotSupportedError:
                logger.warning(
                    "Unverify PIN not supported, session may remain verified"
                )
        del self._session

    def _do_op(self, fn, args, extended=False):
        try:
            return fn(*args)
        except ApduError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                if self._pin:
                    self._session.verify_pin(self._pin, extended)
                    self._unlocked = True
                    return fn(*args)
            raise

    def sign(self, *args):
        return self._do_op(self._session.sign, args)

    def decrypt(self, *args):
        return self._do_op(self._session.decrypt, args, True)

    def authenticate(self, *args):
        return self._do_op(self._session.authenticate, args, True)


class _PrivKey:
    def __init__(self, wrapper, key, fingerprints):
        self._wrapper = wrapper
        self._key = key
        self._fps = fingerprints
        self._fp = bytes(key.fingerprint)

    @property
    def key_size(self):
        # Only called for RSA
        return self._key._key.keymaterial.n.bit_length()

    def decrypt(self, ct, _):
        if self._fps.get(KEY_REF.DEC) == self._fp:
            return self._wrapper.decrypt(ct)
        raise ValueError("Unsupported operation")

    def exchange(self, *args):
        if self._fps.get(KEY_REF.DEC) == self._fp:
            return self._wrapper.decrypt(args[-1])
        raise ValueError("Unsupported operation")

    def sign(self, *args):
        h = args[-1]
        if isinstance(h, ECDSA):
            h = h.algorithm
        if self._fps.get(KEY_REF.SIG) == self._fp:
            return self._wrapper.sign(args[0], h)
        elif self._fps.get(KEY_REF.AUT) == self._fp:
            return self._wrapper.authenticate(args[0], h)
        raise ValueError("Unsupported operation")


class _UnlockedProperty:
    def __init__(self, serial, spec):
        self._serial = serial
        self._orig = spec

    def __get__(self, key, owner):
        if key.keymaterial.s2k.scserial == self._serial:
            return True
        return self._orig.__get__(key, owner)


def _make_privkey(wrapper, key, serial, fingerprints, spec):
    @wraps(spec)
    def inner(keymaterial):
        if keymaterial.s2k.scserial == serial:
            # Find subkey match
            bs = bytes(keymaterial)
            if bs == bytes(key._key.keymaterial):
                subkey = key
            else:
                for sk in key.subkeys.values():
                    if bs == bytes(sk._key.keymaterial):
                        subkey = sk
                        break
                else:
                    raise ValueError("Subkey not part of unlocked PGPKey")
            return _PrivKey(wrapper, subkey, fingerprints)
        return spec(keymaterial)

    return inner


_priv_keys = ("RSAPriv", "ECDSAPriv", "ECDHPriv", "EdDSAPriv")


@contextmanager
def unlock_key(
    session: OpenPgpSession,
    key: PGPKey,
    pin: Optional[str] = None,
    passphrase: Optional[str] = None,
):
    """Connects a PGPKey to an OpenPgpSession so that its keys may be used.

    If pin is given, it will be used to unlock the session as needed. If used, the
    session will be locked upon existing the with-block.

    A passphrase can also be given to unlock any (sub)keys that are passphrase
    protected and not stored on a YubiKey.

    Usage:

        with unlock_key(session, key, pin="123456"):
            key.decrypt(message)
        # key is now locked again
    """
    my_serial = _serial_for_aid(session.aid)
    wrapper = _SessionWrapper(session, pin)
    fingerprints = session.get_fingerprints()

    # This is pretty ugly. It monkey patches a bunch of methods to trick pgpy into
    # thinking the keys are unlocked, and redirect the private key operations to the
    # OpenPgpSession.
    patches = []

    # Patch diverted keys to return unlocked == True
    patches.append(
        mock.patch(
            "pgpy.packet.packets.PrivKeyV4.unlocked",
            spec=True,
            new_callable=_UnlockedProperty,
            serial=my_serial,
        )
    )

    # Patch PrivKey classes to allow redirection to YubiKey
    for cls in _priv_keys:
        patches.append(
            mock.patch(
                f"pgpy.packet.fields.{cls}.__privkey__",
                spec=True,
                new_callable=_make_privkey,
                wrapper=wrapper,
                key=key,
                fingerprints=fingerprints,
                serial=my_serial,
            )
        )

    try:
        # Apply all patches
        for patcher in patches:
            patcher.start()
        if passphrase:  # Also unlock any encrypted keys with passphrase
            with key.unlock(passphrase):
                yield key
        else:
            yield key
    finally:
        wrapper.clear()
        # Restore original methods
        for patcher in patches:
            patcher.stop()
