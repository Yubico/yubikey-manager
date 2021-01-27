from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.yubiotp import (
    YubiOtpSession,
    SLOT,
    HmacSha1SlotConfiguration,
    StaticPasswordSlotConfiguration,
)
from yubikit.management import CAPABILITY, ManagementSession
from ykman.device import connect_to_device
from . import condition
import pytest


@pytest.fixture(params=[OtpConnection, SmartCardConnection])
def conn_type(request, version, transport):
    conn_type = request.param
    if transport == TRANSPORT.NFC:
        if conn_type != SmartCardConnection:
            pytest.skip("Using NFC")
    else:
        if conn_type == SmartCardConnection and (4, 0) <= version < (5, 3):
            pytest.skip("3.x/5.3+ only")
    return conn_type


@pytest.fixture()
@condition.capability(CAPABILITY.OTP)
def session(conn_type, info, device):
    if device.transport == TRANSPORT.NFC:
        with device.open_connection(conn_type) as c:
            yield YubiOtpSession(c)
    else:
        with connect_to_device(info.serial, [conn_type])[0] as c:
            yield YubiOtpSession(c)


def test_status(info, session):
    assert session.get_serial() == info.serial


def not_usb_ccid(conn_type, transport):
    return transport != TRANSPORT.USB or conn_type != SmartCardConnection


@pytest.fixture()
def read_config(session, conn_type, info, transport, await_reboot):
    need_reboot = conn_type == SmartCardConnection and (4, 0) <= info.version < (5, 5)
    if need_reboot and info.version[0] == 4:
        pytest.skip("Can't read config")

    def call():
        otp = session
        if need_reboot:
            protocol = session.backend.protocol
            if transport == TRANSPORT.NFC:
                protocol.connection.connection.disconnect()
                conn = protocol.connection
                conn.connection.connect()
            else:
                ManagementSession(protocol.connection).write_device_config(reboot=True)
                await_reboot()
                conn = connect_to_device(info.serial, [SmartCardConnection])[0]
            otp = YubiOtpSession(conn)
            session.backend = otp.backend
        return otp.get_config_state()

    return call


class TestProgrammingState:
    @pytest.fixture(autouse=True)
    @condition.min_version(2, 1)
    def clear_slots(self, session, read_config):
        state = read_config()
        for slot in (SLOT.ONE, SLOT.TWO):
            if state.is_configured(slot):
                session.delete_slot(slot)

    def test_slot_configured(self, session, read_config):
        state = read_config()
        assert not state.is_configured(SLOT.ONE)
        assert not state.is_configured(SLOT.TWO)
        session.put_configuration(SLOT.ONE, HmacSha1SlotConfiguration(b"a" * 16))

        state = read_config()
        assert state.is_configured(SLOT.ONE)
        assert not state.is_configured(SLOT.TWO)

        session.put_configuration(SLOT.TWO, HmacSha1SlotConfiguration(b"a" * 16))
        state = read_config()
        assert state.is_configured(SLOT.ONE)
        assert state.is_configured(SLOT.TWO)

        session.delete_slot(SLOT.ONE)
        state = read_config()
        assert not state.is_configured(SLOT.ONE)
        assert state.is_configured(SLOT.TWO)

        session.swap_slots()
        state = read_config()
        assert state.is_configured(SLOT.ONE)
        assert not state.is_configured(SLOT.TWO)

        session.delete_slot(SLOT.ONE)
        state = read_config()
        assert not state.is_configured(SLOT.ONE)
        assert not state.is_configured(SLOT.TWO)

    @condition.min_version(3)
    @pytest.mark.parametrize("slot", [SLOT.ONE, SLOT.TWO])
    def test_slot_touch_triggered(self, session, read_config, slot):
        session.put_configuration(slot, HmacSha1SlotConfiguration(b"a" * 16))
        state = read_config()
        assert state.is_configured(slot)
        assert not state.is_touch_triggered(slot)

        session.put_configuration(slot, StaticPasswordSlotConfiguration(b"a"))
        state = read_config()
        assert state.is_configured(slot)
        assert state.is_touch_triggered(slot)

        session.delete_slot(slot)
        state = read_config()
        assert not state.is_configured(slot)
        assert not state.is_touch_triggered(slot)


class TestChallengeResponse:
    @pytest.fixture(autouse=True)
    @condition(not_usb_ccid)
    def clear_slot2(self, session, read_config):
        state = read_config()
        if state.is_configured(SLOT.TWO):
            session.delete_slot(SLOT.TWO)

    def test_calculate_hmac_sha1(self, session):
        session.put_configuration(
            SLOT.TWO,
            HmacSha1SlotConfiguration(
                bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
            ),
        )
        output = session.calculate_hmac_sha1(SLOT.TWO, b"Hi There")
        assert output == bytes.fromhex("b617318655057264e28bc0b6fb378c8ef146be00")
