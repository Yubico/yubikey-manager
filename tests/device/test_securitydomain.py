from yubikit.core import Tlv, TRANSPORT
from yubikit.core.smartcard import ApduError
from yubikit.core.smartcard.scp import (
    ScpKid,
    KeyRef,
    StaticKeys,
    Scp03KeyParams,
    Scp11KeyParams,
)
from yubikit.securitydomain import SecurityDomainSession
from . import condition
from ..util import open_file
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os

import pytest


@pytest.fixture
@condition.min_version(5, 7, 2)
def session(ccid_connection):
    sd = SecurityDomainSession(ccid_connection)
    # Check for the default keyset and only reset if not present, to save time
    default_key = KeyRef(0x1, 0xFF)
    if default_key not in sd.get_key_information():
        sd.reset()
    return sd


def test_card_recognition_data(session):
    data = session.get_card_recognition_data()
    tlvs = Tlv.parse_list(data)
    tags = [x.tag for x in tlvs]
    assert tags[:5] == [0x06, 0x60, 0x63, 0x64, 0x64]


def _verify_auth(sd):
    ref = KeyRef(0x13, 0x7F)
    sd.generate_ec_key(ref)
    sd.delete_key(ref.kid, ref.kvn)


class TestScp03:
    @pytest.fixture(autouse=True)
    def preconditions(self, info, transport):
        if info.is_fips and transport != TRANSPORT.USB:
            pytest.skip("SCP management on YK FIPS over NFC")

    def test_ok(self, session):
        session.authenticate(Scp03KeyParams())
        _verify_auth(session)

    def test_wrong_key(self, session):
        with pytest.raises(ValueError):
            session.authenticate(Scp03KeyParams(keys=StaticKeys(*((b"\1" * 16,) * 3))))

        with pytest.raises(ApduError):
            _verify_auth(session)

    def test_change_key(self, ccid_connection, session):
        session.authenticate(Scp03KeyParams())
        ref = KeyRef(0x1, 0x2)
        keys = StaticKeys(os.urandom(16), os.urandom(16), os.urandom(16))
        session.put_key(ref, keys)

        # Test new key
        session = SecurityDomainSession(ccid_connection)
        session.authenticate(Scp03KeyParams(keys=keys))
        _verify_auth(session)

        # Verify default key is removed
        session = SecurityDomainSession(ccid_connection)
        with pytest.raises(ValueError):
            session.authenticate(Scp03KeyParams())


def _load_scp11_keys(session, kid, kvn):
    sd_ref = KeyRef(kid, kvn)
    oce_ref = KeyRef(0x10, kvn)

    pub_key = session.generate_ec_key(sd_ref)
    with open_file("scp/cert.ca-kloc.ecdsa.pem") as f:
        ca = x509.load_pem_x509_certificate(f.read())
    session.put_key(oce_ref, ca.public_key())
    session.store_ca_issuer(
        oce_ref,
        ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,
    )

    with open_file("scp/cert.ka-kloc.ecdsa.pem") as f:
        ka = x509.load_pem_x509_certificate(f.read())

    with open_file("scp/cert.oce.ecka.pem") as f:
        ecka = x509.load_pem_x509_certificate(f.read())

    with open_file("scp/sk.oce.ecka.pem") as f:
        sk = serialization.load_pem_private_key(f.read(), None)

    return Scp11KeyParams(
        sd_ref,
        pub_key,
        oce_ref,
        sk,
        [ka, ecka],
    )


class TestScp11:
    @pytest.fixture(autouse=True)
    def preconditions(self, info, transport):
        if info.is_fips and transport != TRANSPORT.USB:
            pytest.skip("SCP management on YK FIPS over NFC")

    def test_scp11b_ok(self, session):
        ref = KeyRef(0x13, 0x1)
        chain = session.get_certificate_bundle(ref)
        session.authenticate(Scp11KeyParams(ref, chain[-1].public_key()))
        with pytest.raises(ApduError):
            _verify_auth(session)

    def test_scp11b_wrong_pubkey(self, session):
        ref = KeyRef(0x13, 0x1)
        chain = session.get_certificate_bundle(ref)
        with pytest.raises(InvalidSignature):
            # Using the public key from the intermediate cert instead of the leaf
            session.authenticate(Scp11KeyParams(ref, chain[0].public_key()))

    def test_scp11b_import(self, ccid_connection, session):
        session.authenticate(Scp03KeyParams())

        ref = KeyRef(0x13, 0x2)
        sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
        session.put_key(ref, sk)

        params = Scp11KeyParams(ref, sk.public_key())

        # Authenticate
        session = SecurityDomainSession(ccid_connection)
        session.authenticate(params)

    def test_scp11a_ok(self, ccid_connection, session):
        session.authenticate(Scp03KeyParams())
        kvn = 0x3
        params = _load_scp11_keys(session, ScpKid.SCP11a, kvn)
        # Authenticate
        session = SecurityDomainSession(ccid_connection)
        session.authenticate(params)

        # Verify by deleting keys
        session.delete_key(kvn=kvn)

    def test_scp11a_allowlist(self, ccid_connection, session):
        session.authenticate(Scp03KeyParams())
        kvn = 0x3
        params = _load_scp11_keys(session, ScpKid.SCP11a, kvn)
        serials = [c.serial_number for c in params.certificates]
        session.store_allowlist(params.oce_ref, serials)

        # Authenticate
        session = SecurityDomainSession(ccid_connection)
        session.authenticate(params)

        # Verify by deleting keys
        session.delete_key(kvn=kvn)

    def test_scp11a_allowlist_blocked(self, ccid_connection, session):
        session.authenticate(Scp03KeyParams())

        # Replace default SCP03 keys
        ref = KeyRef(0x1, 0x2)
        keys = StaticKeys(os.urandom(16), os.urandom(16), os.urandom(16))
        session.put_key(ref, keys)
        session.delete_key(kid=ScpKid.SCP11b)

        kvn = 0x3
        params = _load_scp11_keys(session, ScpKid.SCP11a, kvn)
        serials = [1, 2, 3, 4, 5]
        session.store_allowlist(params.oce_ref, serials)

        # Fail authentication
        session = SecurityDomainSession(ccid_connection)
        with pytest.raises(ApduError):
            session.authenticate(params)

        # Remove allowlist
        session.authenticate(Scp03KeyParams(keys=keys))
        session.store_allowlist(params.oce_ref, [])

        # Authenticate
        session = SecurityDomainSession(ccid_connection)
        session.authenticate(params)

    def test_scp11c_ok(self, ccid_connection, session):
        session.authenticate(Scp03KeyParams())
        kvn = 0x3
        params = _load_scp11_keys(session, ScpKid.SCP11c, kvn)
        # Authenticate
        session = SecurityDomainSession(ccid_connection)
        session.authenticate(params)

        # Verify not authenticated
        with pytest.raises(ApduError):
            session.delete_key(kvn=kvn)
