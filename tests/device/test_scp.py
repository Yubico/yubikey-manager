import os

import pytest

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import AID, ApduFormat, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp11KeyParams
from yubikit.securitydomain import SecurityDomainSession

from . import condition


@pytest.fixture
@condition.min_version(5, 7, 2)
def scp_params(ccid_connection):
    ref = KeyRef(0x13, 0x1)
    sd = SecurityDomainSession(ccid_connection)
    if ref not in sd.get_key_information():
        pytest.skip("Default SCP11b key not present, skipping SCP test")
    chain = sd.get_certificate_bundle(ref)
    return Scp11KeyParams(ref, chain[-1].public_key())


@pytest.mark.parametrize("size", (10, 255, 256, 512, 2048))
@pytest.mark.parametrize("format", ApduFormat)
def test_scp_apdus(format, size, ccid_connection, scp_params):
    if format == ApduFormat.EXTENDED and ccid_connection.transport != TRANSPORT.USB:
        pytest.skip("Extended APDU format not used over NFC")

    session = SmartCardProtocol(ccid_connection)
    session.select(AID.MANAGEMENT)
    session.init_scp(scp_params, format == ApduFormat.SHORT)

    payload = os.urandom(size)
    resp = session.send_apdu(0, 1, 0, 0, payload)
    assert resp == payload
