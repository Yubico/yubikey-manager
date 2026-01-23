import os
from enum import Enum

import pytest

from yubikit.core.smartcard import AID, SmartCardProtocol
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


class Configuration(Enum):
    default = 0
    force_short = 1
    no_config = 2

    def __str__(self):
        return self.name


@pytest.mark.parametrize("size", (10, 255, 256, 512, 2048))
@pytest.mark.parametrize("config", Configuration)
def test_scp_apdus(config, size, ccid_connection, scp_params, version):
    protocol = SmartCardProtocol(ccid_connection)
    if config == Configuration.default:
        protocol.configure(version)
    elif config == Configuration.force_short:
        protocol.configure(version, True)
    else:
        pass  # no configuration

    protocol.select(AID.MANAGEMENT)
    protocol.init_scp(scp_params)

    payload = os.urandom(size)
    # ECHO command
    resp = protocol.send_apdu(0, 1, 0, 0, payload)
    assert resp == payload
