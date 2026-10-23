import pytest

from yubikit.core import TRANSPORT, BadResponseError, NotSupportedError, Tlv
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import AID, SW, ApduError, SmartCardConnection
from yubikit.management import (
    FORM_FACTOR,
    ManagementSession,
    StorageInfo,
    StorageStatsEntry,
)


def test_form_factor_from_code():
    for ff in FORM_FACTOR:
        assert ff == FORM_FACTOR.from_code(ff)


STORAGE_RESPONSE = bytes.fromhex(
    "011e0000910195010002000702000300180300040020040006000c0500000000"
)


class StorageConnection(SmartCardConnection):
    def __init__(
        self,
        response=STORAGE_RESPONSE,
        version=b"6.0.0",
        sw=SW.OK,
        transport=TRANSPORT.USB,
    ):
        self.response = response
        self.version = version
        self.sw = sw
        self._transport = transport
        self.sent = []

    @property
    def transport(self):
        return self._transport

    def close(self):
        pass

    def send_and_receive(self, apdu):
        self.sent.append(apdu)
        if apdu[1] == 0xA4:
            assert apdu[5 : 5 + apdu[4]] == AID.MANAGEMENT
            return self.version, SW.OK
        assert apdu[:4] == b"\x00\x30\x00\x00"
        assert apdu[4:] == (
            b"\x00\x00\x00" if self.transport == TRANSPORT.USB else b"\x00"
        )
        return self.response, self.sw


@pytest.mark.parametrize("transport", [TRANSPORT.USB, TRANSPORT.NFC])
def test_read_storage_info(transport):
    connection = StorageConnection(transport=transport)
    with ManagementSession(connection) as session:
        info = session.read_storage_info()
        assert info == StorageInfo(
            [
                StorageStatsEntry(0, 145, 405),
                StorageStatsEntry(1, 2, 7),
                StorageStatsEntry(2, 3, 24),
                StorageStatsEntry(3, 4, 32),
                StorageStatsEntry(4, 6, 12),
                StorageStatsEntry(5, 0, 0),
            ]
        )
        assert info.entry(0) == info.entries[0]
        assert info.entry(5) == info.entries[5]
        assert info.entry(99) is None
        assert len(connection.sent) == 2


def test_read_storage_info_preserves_unknown_ids_and_inline_objects():
    connection = StorageConnection(Tlv(1, bytes.fromhex("ffffffffff0100010000")))
    with ManagementSession(connection) as session:
        assert session.read_storage_info().entries == [
            StorageStatsEntry(0xFF, 65535, 65535),
            StorageStatsEntry(1, 1, 0),
        ]


def test_read_storage_info_empty_response():
    with ManagementSession(StorageConnection(Tlv(1, b""))) as session:
        assert session.read_storage_info() == StorageInfo()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (Tlv(2, b"metadata"), b""),
        (b"", Tlv(2, b"metadata")),
        (Tlv(0x7F49, bytes(128)), Tlv(2, b"metadata")),
        (Tlv(2, b"first"), Tlv(2, b"second")),
    ],
)
def test_read_storage_info_ignores_unknown_tlvs(before, after):
    with ManagementSession(StorageConnection()) as session:
        expected = session.read_storage_info()
    with ManagementSession(
        StorageConnection(before + STORAGE_RESPONSE + after)
    ) as session:
        assert session.read_storage_info() == expected


@pytest.mark.parametrize(
    "response",
    [
        b"",
        b"\x02\x00",
        b"\x01",
        b"\x01\x05\x00",
        b"\x01\x00\x01\x00",
        b"\x01\x00\xff",
        b"\x02\x00\x03\x00",
        b"\x01\x00\x02\x00\x01\x00",
        b"\x01\x00\x02\x01",
        b"\x02\x01",
        *[Tlv(1, bytes(size)) for size in [1, 2, 3, 4, 6, 7, 8, 9]],
    ],
)
def test_read_storage_info_rejects_malformed_response(response):
    with ManagementSession(StorageConnection(response)) as session:
        with pytest.raises(BadResponseError):
            session.read_storage_info()


@pytest.mark.parametrize("version", [b"4.4.5", b"5.7.2"])
def test_read_storage_info_rejects_older_firmware_before_command(version):
    connection = StorageConnection(version=version)
    with ManagementSession(connection) as session:
        with pytest.raises(NotSupportedError, match="6.0.0"):
            session.read_storage_info()
        assert len(connection.sent) == 1


@pytest.mark.parametrize(
    "sw", [SW.INVALID_INSTRUCTION, SW.SECURITY_CONDITION_NOT_SATISFIED]
)
def test_read_storage_info_propagates_apdu_error(sw):
    with ManagementSession(StorageConnection(b"error", sw=sw)) as session:
        with pytest.raises(ApduError) as error:
            session.read_storage_info()
        assert error.value.sw == sw
        assert error.value.data == b"error"


class StorageFidoConnection(FidoConnection):
    @property
    def device_version(self):
        return (6, 0, 0)

    @property
    def capabilities(self):
        return 4

    def close(self):
        pass

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        pytest.fail("Storage info must not send a FIDO command")


class StorageOtpConnection(OtpConnection):
    def close(self):
        pass

    def receive(self):
        return b"\x00\x06\x00\x00\x00\x00\x00\x00"

    def send(self, data):
        pytest.fail("Storage info must not send an OTP command")


@pytest.mark.parametrize(
    "connection_type", [StorageFidoConnection, StorageOtpConnection]
)
def test_read_storage_info_rejects_non_ccid_connection(connection_type):
    with ManagementSession(connection_type()) as session:
        with pytest.raises(NotImplementedError, match="CCID"):
            session.read_storage_info()


def test_native_read_storage_info_rejects_closed_session():
    from _yubikit_native.sessions import ManagementSessionCcid

    session = ManagementSessionCcid(StorageConnection())
    session.close()
    with pytest.raises(RuntimeError, match="Session is closed"):
        session.read_storage_info()
