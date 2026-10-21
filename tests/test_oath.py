#  vim: set fileencoding=utf-8 :

import pytest

from yubikit.core import TRANSPORT, Tlv
from yubikit.core.smartcard import SW, ApduError, SmartCardConnection
from yubikit.oath import (
    HASH_ALGORITHM,
    OATH_TYPE,
    CredentialData,
    OathSession,
)


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("otpauth://totp/account?secret=abba", None),
        ("otpauth://totp/account?secret=abba&issuer=Test", "Test"),
        ("otpauth://totp/Test:account?secret=abba", "Test"),
        ("otpauth://totp/TestA:account?secret=abba&issuer=TestB", "TestB"),
    ],
)
def test_parse_uri_issuer(uri, expected):
    assert CredentialData.parse_uri(uri).issuer == expected


def test_parse_uri_full_payload():
    data = CredentialData.parse_uri(
        "otpauth://totp/Issuer:account"
        "?secret=abba&issuer=Issuer"
        "&algorithm=SHA256&digits=7"
        "&period=20&counter=5"
    )
    assert data.secret == b"\0B"
    assert data.issuer == "Issuer"
    assert data.name == "account"
    assert data.oath_type == OATH_TYPE.TOTP
    assert data.hash_algorithm == HASH_ALGORITHM.SHA256
    assert data.digits == 7
    assert data.period == 20
    assert data.counter == 5


class ResetConnection(SmartCardConnection):
    def __init__(self, outcome):
        self.outcome = outcome
        self.sent = []
        self.did_reset = False
        self.closed = False

    @property
    def transport(self):
        return TRANSPORT.USB

    def close(self):
        self.closed = True

    def send_and_receive(self, apdu):
        self.sent.append(apdu)
        if apdu[1] == 0xA4:
            salt = b"new salt" if self.did_reset else b"old salt"
            return Tlv(0x79, b"\x05\x07\x02") + Tlv(0x71, salt), SW.OK
        if apdu[1] == 0x04:
            assert apdu[:4] == b"\x00\x04\xde\xad"
            if self.outcome == "transport":
                raise OSError("Reset transport failure")
            if self.outcome == "status":
                return b"", SW.SECURITY_CONDITION_NOT_SATISFIED
            self.did_reset = True
            return b"", SW.OK
        if apdu[1] == 0xA1:
            return b"", SW.OK
        pytest.fail(f"Unexpected APDU: {apdu.hex()}")


@pytest.mark.parametrize("outcome", ("success", "status", "transport"))
def test_reset_closes_session_and_restores_connection(outcome):
    connection = ResetConnection(outcome)
    oath = OathSession(connection)
    old_id = oath.device_id
    version = oath.version
    if outcome == "success":
        assert oath.reset() is None
    elif outcome == "status":
        with pytest.raises(ApduError) as exc:
            oath.reset()
        assert exc.value.sw == SW.SECURITY_CONDITION_NOT_SATISFIED
    else:
        with pytest.raises(RuntimeError, match="Reset transport failure"):
            oath.reset()

    assert len(connection.sent) == 2
    assert connection._session is None
    assert oath._connection is None
    assert not connection.closed
    assert oath.device_id == old_id
    assert oath.version == version

    credential = CredentialData("name", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, b"secret")
    for operation in (
        oath.reset,
        oath.list_credentials,
        lambda: oath.has_key,
        lambda: oath.locked,
        lambda: oath._native.version,
        lambda: oath._native.device_id,
        lambda: oath.derive_key("password"),
        lambda: oath.validate(bytes(16)),
        lambda: oath.set_key(bytes(16)),
        oath.unset_key,
        lambda: oath.put_credential(credential),
        lambda: oath.delete_credential(b"name"),
        lambda: oath.rename_credential(b"name", "newname"),
        lambda: oath.calculate(b"name", b"challenge"),
        oath.calculate_all,
    ):
        with pytest.raises(RuntimeError, match="Session is closed"):
            operation()
    oath.close()
    oath.close()
    assert len(connection.sent) == 2

    with OathSession(connection) as reopened:
        assert (reopened.device_id != old_id) == (outcome == "success")
        assert reopened.list_credentials() == []
