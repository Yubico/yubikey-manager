from functools import partial

import pytest


def pytest_addoption(parser):
    parser.addoption("--device", action="store", type=int)
    parser.addoption("--no-serial", action="store_true")


@pytest.fixture(
    params=(
        "OathSession",
        "PivSession",
        "OpenPgpSession",
        "HsmAuthSession",
        "ManagementSessionCcid",
        "YubiOtpSessionCcid",
        "Ctap2SessionCcid",
        "WebAuthnClientCcid",
    )
)
def scp_session_constructor(request):
    from _yubikit_native import sessions

    constructor = getattr(sessions, request.param)
    if request.param == "WebAuthnClientCcid":
        return partial(constructor, user_interaction=None, client_data_collector=None)
    return constructor


@pytest.fixture(params=("key_enc", "key_mac", "key_dek", "type"))
def invalid_scp_params(request):
    from yubikit.core.smartcard.scp import Scp03KeyParams, StaticKeys

    if request.param == "type":
        return object()
    keys = StaticKeys(
        **{
            name: bytes(15 if name == request.param else 16)
            for name in ("key_enc", "key_mac", "key_dek")
        }
    )
    return Scp03KeyParams(keys=keys)
