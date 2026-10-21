import pytest

from yubikit.core.fido import FidoConnection
from yubikit.ctap2 import ClientPin, Ctap2Session, PinProtocol


def encode_map(entries):
    assert len(entries) < 24
    return bytes([0xA0 + len(entries)]) + b"".join(k + v for k, v in entries)


class CtapConnection(FidoConnection):
    def __init__(self, info, peer=None, protocol=1):
        self.info = info
        self.peer = peer
        self.protocol = protocol
        self.requests = []

    @property
    def device_version(self):
        return (5, 7, 2)

    @property
    def capabilities(self):
        return 4

    def close(self):
        pass

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == 0x10
        self.requests.append(data)
        if data == b"\x04":
            return b"\x00" + self.info
        if data == b"\x06\xa2\x01" + bytes([self.protocol]) + b"\x02\x02":
            assert self.peer is not None
            return b"\x00" + encode_map([(b"\x01", self.peer)])
        assert data[:6] == b"\x06\xa5\x01" + bytes([self.protocol]) + b"\x02\x03"
        assert self.peer is not None
        return b"\x00"


@pytest.mark.parametrize(
    "value",
    [
        b"\xa2\x01\x61a\xf5\x61b",
        b"\xa2\xf5\x61a\x01\x61b",
        b"\xa2\x00\x61a\xf4\x61b",
        b"\xa2\xf4\x61a\x00\x61b",
        b"\x81\xa2\x01\x61a\xf5\x61b",
        b"\xa1\x61x\xa2\x01\x61a\xf5\x61b",
    ],
)
def test_cbor_to_python_rejects_colliding_keys(value):
    connection = CtapConnection(b"\xa1\x13\xa1\x64test" + value)
    with Ctap2Session(connection) as session:
        with pytest.raises(ValueError, match="CBOR map keys collide in Python"):
            session.get_info()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"\xa2\x01\x61a\xf4\x61b", {1: "a", False: "b"}),
        (b"\xa2\x00\x61a\xf5\x61b", {0: "a", True: "b"}),
        (b"\xa2\x61x\x01\x41x\x02", {"x": 1, b"x": 2}),
        (b"\x81\xa1\xf5\x61a", [{True: "a"}]),
    ],
)
def test_cbor_to_python_preserves_distinct_keys(value, expected):
    connection = CtapConnection(b"\xa1\x13\xa1\x64test" + value)
    with Ctap2Session(connection) as session:
        assert session.get_info()["certifications"]["test"] == expected


@pytest.mark.parametrize("protocol", [1, 2])
@pytest.mark.parametrize("label", [b"\x01", b"\x03", b"\x20"])
@pytest.mark.parametrize("replacement", [None, b"\x00", b"\xf5", b"\x61x", b"\x41\x01"])
def test_client_pin_rejects_invalid_peer_before_set_pin(protocol, label, replacement):
    peer = make_peer(label, replacement)
    connection = CtapConnection(b"\xa1\x06\x81" + bytes([protocol]), peer, protocol)
    with Ctap2Session(connection) as session:
        with ClientPin(session, PinProtocol(protocol)) as client_pin:
            with pytest.raises(
                ValueError, match="key agreement failed: invalid peer key"
            ):
                client_pin.set_pin("2468")
        assert connection.requests == [
            b"\x04",
            b"\x06\xa2\x01" + bytes([protocol]) + b"\x02\x02",
        ]
        assert session.get_info()["pin_uv_protocols"] == [protocol]


def make_peer(label=None, replacement=None):
    entries = [
        (b"\x01", b"\x02"),
        (b"\x03", b"\x38\x18"),
        (b"\x20", b"\x01"),
        (
            b"\x21",
            b"\x58\x20"
            + bytes.fromhex(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            ),
        ),
        (
            b"\x22",
            b"\x58\x20"
            + bytes.fromhex(
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            ),
        ),
    ]
    if label is not None:
        entries = [(k, v) for k, v in entries if k != label]
        if replacement is not None:
            entries.append((label, replacement))
    return encode_map(entries)


@pytest.mark.parametrize("protocol", [1, 2])
def test_client_pin_accepts_valid_peer(protocol):
    connection = CtapConnection(
        b"\xa1\x06\x81" + bytes([protocol]), make_peer(), protocol
    )
    with Ctap2Session(connection) as session:
        with ClientPin(session, PinProtocol(protocol)) as client_pin:
            client_pin.set_pin("2468")
        assert len(connection.requests) == 3
