from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, x25519, padding
from cryptography.hazmat.primitives import hashes
from yubikit.openpgp import (
    OpenPgpSession,
    KEY_REF,
    RSA_SIZE,
    OID,
    KdfIterSaltedS2k,
    KdfNone,
)
from yubikit.management import CAPABILITY
from yubikit.core.smartcard import ApduError
from . import condition

import pytest
import time


E = 65537
DEFAULT_PIN = "123456"
NON_DEFAULT_PIN = "654321"
DEFAULT_ADMIN_PIN = "12345678"
NON_DEFAULT_ADMIN_PIN = "87654321"


@pytest.fixture
@condition.capability(CAPABILITY.OPENPGP)
def session(ccid_connection):
    pgp = OpenPgpSession(ccid_connection)
    pgp.reset()
    return pgp


def not_roca(version):
    """ROCA affected"""
    return not ((4, 2, 0) <= version < (4, 3, 5))


def test_import_requires_admin(session):
    priv = rsa.generate_private_key(E, RSA_SIZE.RSA2048, default_backend())
    with pytest.raises(ApduError):
        session.put_key(KEY_REF.SIG, priv)


@condition.check(not_roca)
def test_generate_requires_admin(session):
    with pytest.raises(ApduError):
        session.generate_rsa_key(KEY_REF.SIG, RSA_SIZE.RSA2048)


@condition.min_version(5, 2)
@pytest.mark.parametrize("oid", [x for x in OID if "25519" not in x.name])
def test_import_sign_ecdsa(session, oid):
    priv = ec.generate_private_key(getattr(ec, oid.name)())
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.put_key(KEY_REF.SIG, priv)
    message = b"Hello world"
    session.verify_pin(DEFAULT_PIN)
    sig = session.sign(message, hashes.SHA256())
    priv.public_key().verify(sig, message, ec.ECDSA(hashes.SHA256()))


@condition.min_version(5, 2)
def test_import_sign_eddsa(session):
    priv = ed25519.Ed25519PrivateKey.generate()
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.put_key(KEY_REF.SIG, priv)
    message = b"Hello world"
    session.verify_pin(DEFAULT_PIN)
    sig = session.sign(message, hashes.SHA256())
    priv.public_key().verify(sig, message)


@condition.min_version(5, 2)
@pytest.mark.parametrize("oid", [x for x in OID if "25519" not in x.name])
def test_import_ecdh(session, oid):
    priv = ec.generate_private_key(getattr(ec, oid.name)())
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.put_key(KEY_REF.DEC, priv)
    e_priv = ec.generate_private_key(getattr(ec, oid.name)())
    shared1 = e_priv.exchange(ec.ECDH(), priv.public_key())
    session.verify_pin(DEFAULT_PIN, extended=True)
    shared2 = session.decrypt(e_priv.public_key())

    assert shared1 == shared2


@condition.min_version(5, 2)
def test_import_ecdh_x25519(session):
    priv = x25519.X25519PrivateKey.generate()
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.put_key(KEY_REF.DEC, priv)
    e_priv = x25519.X25519PrivateKey.generate()
    shared1 = e_priv.exchange(priv.public_key())
    session.verify_pin(DEFAULT_PIN, extended=True)
    shared2 = session.decrypt(e_priv.public_key())

    assert shared1 == shared2


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_import_sign_rsa(session, key_size, info):
    if key_size != 2048:
        if info.version[0] < 4:
            pytest.skip(f"RSA {key_size} requires YuibKey 4 or later")
        elif info.version[0] == 4 and info.is_fips:
            pytest.skip(f"RSA {key_size} not supported on YubiKey 4 FIPS")
    priv = rsa.generate_private_key(E, key_size, default_backend())
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.put_key(KEY_REF.SIG, priv)
    if 0 < info.version[0] < 5:
        # Keys don't work without a generation time (or fingerprint)
        session.set_generation_time(KEY_REF.SIG, int(time.time()))

    message = b"Hello world"
    session.verify_pin(DEFAULT_PIN)
    sig = session.sign(message, hashes.SHA256())
    priv.public_key().verify(sig, message, padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_import_decrypt_rsa(session, key_size, info):
    if key_size != 2048:
        if info.version[0] < 4:
            pytest.skip(f"RSA {key_size} requires YuibKey 4 or later")
        elif info.version[0] == 4 and info.is_fips:
            pytest.skip(f"RSA {key_size} not supported on YubiKey 4 FIPS")
    priv = rsa.generate_private_key(E, key_size, default_backend())
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.put_key(KEY_REF.DEC, priv)
    if info.version[0] < 5:
        # Keys don't work without a generation time (or fingerprint)
        session.set_generation_time(KEY_REF.DEC, int(time.time()))

    message = b"Hello world"
    cipher = priv.public_key().encrypt(message, padding.PKCS1v15())
    session.verify_pin(DEFAULT_PIN, extended=True)
    plain = session.decrypt(cipher)

    assert message == plain


@condition.check(not_roca)
@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_generate_rsa(session, key_size, info):
    if key_size != 2048:
        if info.version[0] < 4:
            pytest.skip(f"RSA {key_size} requires YuibKey 4 or later")
        elif info.version[0] == 4 and info.is_fips:
            pytest.skip(f"RSA {key_size} not supported on YubiKey 4 FIPS")
    session.verify_admin(DEFAULT_ADMIN_PIN)
    pub = session.generate_rsa_key(KEY_REF.SIG, RSA_SIZE(key_size))
    if info.version[0] < 5:
        # Keys don't work without a generation time (or fingerprint)
        session.set_generation_time(KEY_REF.SIG, int(time.time()))

    assert pub.key_size == key_size

    message = b"Hello world"
    session.verify_pin(DEFAULT_PIN)
    sig = session.sign(message, hashes.SHA256())
    pub.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())


@condition.min_version(5, 2)
@pytest.mark.parametrize("oid", [x for x in OID if "25519" not in x.name])
def test_generate_ecdsa(session, oid):
    session.verify_admin(DEFAULT_ADMIN_PIN)
    pub = session.generate_ec_key(KEY_REF.SIG, oid)
    message = b"Hello world"
    session.verify_pin(DEFAULT_PIN)
    sig = session.sign(message, hashes.SHA256())
    pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))


@condition.min_version(5, 2)
def test_generate_ed25519(session):
    session.verify_admin(DEFAULT_ADMIN_PIN)
    pub = session.generate_ec_key(KEY_REF.SIG, OID.Ed25519)
    message = b"Hello world"
    session.verify_pin(DEFAULT_PIN)
    sig = session.sign(message, hashes.SHA256())
    pub.verify(sig, message)


@condition.min_version(5, 2)
def test_generate_x25519(session):
    session.verify_admin(DEFAULT_ADMIN_PIN)
    pub = session.generate_ec_key(KEY_REF.DEC, OID.X25519)

    e_priv = x25519.X25519PrivateKey.generate()
    shared1 = e_priv.exchange(pub)
    session.verify_pin(DEFAULT_PIN, extended=True)
    shared2 = session.decrypt(e_priv.public_key())

    assert shared1 == shared2


@condition.min_version(5, 2)
def test_kdf(session):
    with pytest.raises(ApduError):
        session.set_kdf(KdfIterSaltedS2k.create())

    session.change_admin(DEFAULT_ADMIN_PIN, NON_DEFAULT_ADMIN_PIN)
    session.verify_admin(NON_DEFAULT_ADMIN_PIN)
    session.set_kdf(KdfIterSaltedS2k.create())
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.verify_pin(DEFAULT_PIN)

    session.change_admin(DEFAULT_ADMIN_PIN, NON_DEFAULT_ADMIN_PIN)
    session.change_pin(DEFAULT_PIN, NON_DEFAULT_PIN)
    session.verify_pin(NON_DEFAULT_PIN)

    session.set_kdf(KdfNone())
    session.verify_admin(DEFAULT_ADMIN_PIN)
    session.verify_pin(DEFAULT_PIN)


@condition.min_version(5, 2)
def test_attestation(session):
    if not session.get_key_information()[KEY_REF.ATT]:
        pytest.skip("No attestation key")

    session.verify_admin(DEFAULT_ADMIN_PIN)
    pub = session.generate_ec_key(KEY_REF.SIG, OID.SECP256R1)

    session.verify_pin(DEFAULT_PIN)
    cert = session.attest_key(KEY_REF.SIG)

    assert cert.public_key() == pub
