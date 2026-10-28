import pytest
from yubikit.core import TRANSPORT, Tlv
from yubikit.core.smartcard import SW, ApduError, SmartCardConnection
from yubikit.piv import MANAGEMENT_KEY_TYPE, PivSession
from yubikit.pivman import (
    OBJECT_ID_PIVMAN_DATA,
    OBJECT_ID_PIVMAN_PROTECTED_DATA,
    PivmanData,
    PivmanProtectedData,
    get_pivman_data,
    get_pivman_protected_data,
    pivman_set_mgm_key,
)


class PivmanConnection(SmartCardConnection):
    def __init__(self):
        self.objects = {}
        self.read_errors = {}
        self.write_errors = {}
        self.key_error = None
        self.key_type = MANAGEMENT_KEY_TYPE.TDES
        self.events = []

    @property
    def transport(self):
        return TRANSPORT.USB

    def close(self):
        pass

    def send_and_receive(self, apdu):
        instruction = apdu[1]
        if instruction == 0xA4:
            return b"", SW.OK
        if instruction == 0xFD:
            return b"\x05\x07\x01", SW.OK
        if instruction == 0xF7:
            return Tlv(1, bytes([self.key_type])) + Tlv(2, b"\x00\x01"), SW.OK
        if instruction == 0xFA:
            self.events.append(("attempts", apdu[2], apdu[3]))
            return b"", SW.OK

        if apdu[4] == 0:
            length = int.from_bytes(apdu[5:7], "big")
            data = apdu[7 : 7 + length]
        else:
            data = apdu[5 : 5 + apdu[4]]

        if instruction == 0xFF:
            key = Tlv(data[1:])
            assert key.tag == 0x9B
            self.events.append(("key", data[0], key.value, apdu[3]))
            if self.key_error is not None:
                return b"", self.key_error
            self.key_type = MANAGEMENT_KEY_TYPE(data[0])
            return b"", SW.OK

        fields = Tlv.parse_dict(data)
        object_id = int.from_bytes(fields[0x5C], "big")
        if instruction == 0xCB:
            self.events.append(("read", object_id))
            error = self.read_errors.get(object_id)
            if isinstance(error, Exception):
                raise error
            if error is not None:
                return b"", error
            if object_id not in self.objects:
                return b"", SW.FILE_NOT_FOUND
            return Tlv(0x53, self.objects[object_id]), SW.OK
        if instruction == 0xDB:
            self.events.append(("write", object_id, fields[0x53]))
            error = self.write_errors.get(object_id)
            if isinstance(error, Exception):
                raise error
            if error is not None:
                return b"", error
            self.objects[object_id] = fields[0x53]
            return b"", SW.OK
        pytest.fail(f"Unexpected APDU: {apdu.hex()}")


@pytest.fixture
def card():
    return PivmanConnection()


@pytest.fixture
def session(card):
    with PivSession(card) as session:
        yield session


READERS = [
    (get_pivman_data, OBJECT_ID_PIVMAN_DATA, 0x80),
    (get_pivman_protected_data, OBJECT_ID_PIVMAN_PROTECTED_DATA, 0x88),
]
KEY = bytes(range(32))


@pytest.mark.parametrize("flags", [0, 1, 2, 3])
def test_legacy_salt_does_not_protect_management_key(flags):
    data = PivmanData(Tlv(0x80, Tlv(0x81, bytes([flags])) + Tlv(0x82, bytes(16))))
    assert data.has_stored_key == bool(flags & 0x02)
    fields = {0x82: bytes(16)}
    if flags:
        fields[0x81] = bytes([flags])
    assert Tlv.parse_dict(Tlv(data.get_bytes()).value) == fields


@pytest.mark.parametrize(("reader", "object_id", "tag"), READERS)
def test_read_missing_metadata(session, card, reader, object_id, tag):
    assert reader(session).get_bytes() == b""
    assert card.events == [("read", object_id)]


@pytest.mark.parametrize(("reader", "object_id", "tag"), READERS)
@pytest.mark.parametrize(
    "sw", [SW.SECURITY_CONDITION_NOT_SATISFIED, SW.INCORRECT_PARAMETERS]
)
def test_read_errors_propagate(session, card, reader, object_id, tag, sw):
    card.read_errors[object_id] = sw
    with pytest.raises(ApduError) as exc:
        reader(session)
    assert exc.value.sw == sw


@pytest.mark.parametrize(("reader", "object_id", "tag"), READERS)
def test_transport_errors_propagate(session, card, reader, object_id, tag):
    card.read_errors[object_id] = OSError("disconnected")
    with pytest.raises(RuntimeError, match="disconnected"):
        reader(session)


@pytest.mark.parametrize(("reader", "object_id", "tag"), READERS)
@pytest.mark.parametrize("malformed", ["empty", "wrong-tag", "inner", "trailing"])
def test_malformed_metadata_raises_value_error(
    session, card, reader, object_id, tag, malformed
):
    card.objects[object_id] = {
        "empty": b"",
        "wrong-tag": Tlv(0x90),
        "inner": Tlv(tag, b"\x81\x02\x01"),
        "trailing": Tlv(tag) + Tlv(0x90),
    }[malformed]
    with pytest.raises(ValueError):
        reader(session)


@pytest.mark.parametrize(("tag", "value"), [(0x81, b""), (0x81, b"\x01\x02")])
def test_invalid_public_fields_rejected(session, card, tag, value):
    card.objects[OBJECT_ID_PIVMAN_DATA] = Tlv(0x80, Tlv(tag, value))
    with pytest.raises(ValueError):
        get_pivman_data(session)
    with pytest.raises(ValueError):
        pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256)
    assert not any(event[0] == "key" for event in card.events)


def test_metadata_adapters_preserve_unknown_fields():
    public = PivmanData(
        Tlv(
            0x80,
            Tlv(0x81, b"\x03") + Tlv(0x82, b"salt") + Tlv(0x83, b"x") + Tlv(0x90, b"y"),
        )
    )
    public.mgm_key_protected = False
    fields = Tlv.parse_dict(Tlv(public.get_bytes()).value)
    assert fields == {0x81: b"\x01", 0x82: b"salt", 0x83: b"x", 0x90: b"y"}

    protected = PivmanProtectedData(Tlv(0x88, Tlv(0x89, b"key") + Tlv(0x90, b"x")))
    protected.key = None
    assert protected.get_bytes() == Tlv(0x88, Tlv(0x90, b"x"))


@pytest.mark.parametrize("value", [b"", b"x", bytes(4), bytes(16)])
def test_legacy_fields_preserved_without_interpretation(session, card, value):
    raw = Tlv(0x80, Tlv(0x82, value) + Tlv(0x83, value))
    card.objects[OBJECT_ID_PIVMAN_DATA] = raw
    data = get_pivman_data(session)
    assert not data.has_stored_key
    assert data.get_bytes() == raw
    pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256, store_on_device=True)
    fields = Tlv.parse_dict(Tlv(card.objects[OBJECT_ID_PIVMAN_DATA]).value)
    assert fields == {0x81: b"\x02", 0x82: value, 0x83: value}


@pytest.mark.parametrize("touch", [False, True])
@pytest.mark.parametrize("store", [False, True])
def test_unchanged_public_metadata_is_not_written(session, card, touch, store):
    flags = b"\x03" if store else b"\x01"
    raw = Tlv(0x80, Tlv(0x81, flags) + Tlv(0x90, b"unknown"))
    card.objects[OBJECT_ID_PIVMAN_DATA] = raw
    pivman_set_mgm_key(
        session, KEY, MANAGEMENT_KEY_TYPE.AES256, touch=touch, store_on_device=store
    )
    expected = [("read", OBJECT_ID_PIVMAN_DATA)]
    if store:
        expected.append(("read", OBJECT_ID_PIVMAN_PROTECTED_DATA))
    expected.append(("key", MANAGEMENT_KEY_TYPE.AES256, KEY, 0xFE if touch else 0xFF))
    if store:
        expected.append(
            ("write", OBJECT_ID_PIVMAN_PROTECTED_DATA, Tlv(0x88, Tlv(0x89, KEY)))
        )
    assert card.events == expected
    assert card.objects[OBJECT_ID_PIVMAN_DATA] == raw
    assert session.management_key_type == MANAGEMENT_KEY_TYPE.AES256


def test_duplicate_flags_use_last_value_consistently(session, card):
    raw = Tlv(0x80, Tlv(0x81, b"\x02") + Tlv(0x81, b"\x01"))
    card.objects[OBJECT_ID_PIVMAN_DATA] = raw
    assert not get_pivman_data(session).has_stored_key
    card.events.clear()
    pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256)
    assert [event[0] for event in card.events] == ["read", "key"]
    assert card.objects[OBJECT_ID_PIVMAN_DATA] == raw


def test_storing_key_preserves_unknown_metadata(session, card):
    card.objects[OBJECT_ID_PIVMAN_DATA] = Tlv(
        0x80, Tlv(0x81, b"\x01") + Tlv(0x82, bytes(16)) + Tlv(0x90, b"public")
    )
    card.objects[OBJECT_ID_PIVMAN_PROTECTED_DATA] = Tlv(0x88, Tlv(0x90, b"protected"))
    pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256, store_on_device=True)
    assert Tlv.parse_dict(Tlv(card.objects[OBJECT_ID_PIVMAN_DATA]).value) == {
        0x81: b"\x03",
        0x82: bytes(16),
        0x90: b"public",
    }
    assert Tlv.parse_dict(Tlv(card.objects[OBJECT_ID_PIVMAN_PROTECTED_DATA]).value) == {
        0x89: KEY,
        0x90: b"protected",
    }
    assert [event[0] for event in card.events] == [
        "read",
        "read",
        "key",
        "write",
        "write",
    ]


@pytest.mark.parametrize("malformed", [False, True])
def test_storing_requires_readable_protected_metadata(session, card, malformed):
    if malformed:
        card.objects[OBJECT_ID_PIVMAN_PROTECTED_DATA] = b"invalid"
        error = ValueError
    else:
        card.read_errors[OBJECT_ID_PIVMAN_PROTECTED_DATA] = (
            SW.SECURITY_CONDITION_NOT_SATISFIED
        )
        error = ApduError
    with pytest.raises(error):
        pivman_set_mgm_key(
            session, KEY, MANAGEMENT_KEY_TYPE.AES256, store_on_device=True
        )
    assert [event[0] for event in card.events] == ["read", "read"]
    assert session.management_key_type == MANAGEMENT_KEY_TYPE.TDES


def test_storing_in_missing_protected_object(session, card):
    pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256, store_on_device=True)
    assert get_pivman_data(session).has_stored_key
    assert get_pivman_protected_data(session).key == KEY


def test_switching_away_from_stored_key_without_pin(session, card):
    card.objects[OBJECT_ID_PIVMAN_DATA] = Tlv(0x80, Tlv(0x81, b"\x03"))
    card.read_errors[OBJECT_ID_PIVMAN_PROTECTED_DATA] = (
        SW.SECURITY_CONDITION_NOT_SATISFIED
    )
    pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256)
    assert card.objects[OBJECT_ID_PIVMAN_DATA] == Tlv(0x80, Tlv(0x81, b"\x01"))
    assert [event[0] for event in card.events] == ["read", "read", "key", "write"]


@pytest.mark.parametrize(
    "error", [None, SW.SECURITY_CONDITION_NOT_SATISFIED, OSError("lost")]
)
def test_clearing_old_stored_key(session, card, error):
    card.objects[OBJECT_ID_PIVMAN_DATA] = Tlv(0x80, Tlv(0x81, b"\x02"))
    original = Tlv(0x88, Tlv(0x89, b"old key") + Tlv(0x90, b"unknown"))
    card.objects[OBJECT_ID_PIVMAN_PROTECTED_DATA] = original
    if error is not None:
        card.write_errors[OBJECT_ID_PIVMAN_PROTECTED_DATA] = error
    if isinstance(error, OSError):
        with pytest.raises(RuntimeError, match="lost"):
            pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256)
    else:
        pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256)
    assert card.objects[OBJECT_ID_PIVMAN_DATA] == b""
    assert card.objects[OBJECT_ID_PIVMAN_PROTECTED_DATA] == (
        Tlv(0x88, Tlv(0x90, b"unknown")) if error is None else original
    )
    assert session.management_key_type == MANAGEMENT_KEY_TYPE.AES256


@pytest.mark.parametrize(
    "protected",
    [b"", Tlv(0x88), Tlv(0x88, Tlv(0x89)), Tlv(0x88, Tlv(0x89, b"old") + Tlv(0x89))],
)
def test_no_key_cleanup_when_protected_key_is_missing(session, card, protected):
    card.objects[OBJECT_ID_PIVMAN_DATA] = Tlv(0x80, Tlv(0x81, b"\x02"))
    if protected:
        card.objects[OBJECT_ID_PIVMAN_PROTECTED_DATA] = protected
    pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256)
    assert [event[:2] for event in card.events if event[0] == "write"] == [
        ("write", OBJECT_ID_PIVMAN_DATA)
    ]


@pytest.mark.parametrize(
    "object_id", [OBJECT_ID_PIVMAN_DATA, OBJECT_ID_PIVMAN_PROTECTED_DATA]
)
def test_write_errors_propagate_and_management_key_type_stays_current(
    session, card, object_id
):
    card.write_errors[object_id] = SW.SECURITY_CONDITION_NOT_SATISFIED
    with pytest.raises(ApduError):
        pivman_set_mgm_key(
            session, KEY, MANAGEMENT_KEY_TYPE.AES256, store_on_device=True
        )
    assert session.management_key_type == MANAGEMENT_KEY_TYPE.AES256
    assert card.key_type == MANAGEMENT_KEY_TYPE.AES256


def test_failed_key_change_does_not_update_metadata_or_cached_algorithm(session, card):
    card.key_error = SW.SECURITY_CONDITION_NOT_SATISFIED
    with pytest.raises(ApduError):
        pivman_set_mgm_key(
            session, KEY, MANAGEMENT_KEY_TYPE.AES256, store_on_device=True
        )
    assert not any(event[0] == "write" for event in card.events)
    assert session.management_key_type == MANAGEMENT_KEY_TYPE.TDES


def test_invalid_key_rejected_before_io(session, card):
    with pytest.raises(ValueError):
        pivman_set_mgm_key(session, b"short", MANAGEMENT_KEY_TYPE.AES256)
    assert card.events == []


def test_closed_session_rejected(session, card):
    session.close()
    with pytest.raises(RuntimeError, match="Session is closed"):
        get_pivman_data(session)
    with pytest.raises(RuntimeError, match="Session is closed"):
        pivman_set_mgm_key(session, KEY, MANAGEMENT_KEY_TYPE.AES256)
    assert card.events == []


def test_setting_pin_retries_preserves_unknown_metadata(session, card):
    card.objects[OBJECT_ID_PIVMAN_DATA] = Tlv(
        0x80, Tlv(0x81, b"\x03") + Tlv(0x82, b"salt") + Tlv(0x83, b"x")
    )
    original = card.objects.copy()
    session.set_pin_attempts(5, 6)
    assert card.events == [("attempts", 5, 6)]
    assert card.objects == original
