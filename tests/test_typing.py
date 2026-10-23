from typing import assert_type

from yubikit.core import Closable
from yubikit.yubiotp import (
    HmacSha1SlotConfiguration,
    HotpSlotConfiguration,
    StaticPasswordSlotConfiguration,
    StaticTicketSlotConfiguration,
    UpdateConfiguration,
    YubiOtpSlotConfiguration,
)


def test_context_manager_preserves_subclass():
    class Resource(Closable):
        closed = False

        def close(self) -> None:
            self.closed = True

    resource = Resource()
    with resource as entered:
        assert_type(entered, Resource)
        assert entered is resource
        assert not resource.closed
    assert resource.closed


def test_configuration_builders_preserve_subclass():
    hmac = HmacSha1SlotConfiguration(bytes(20))
    assert_type(hmac.serial_api_visible(True), HmacSha1SlotConfiguration)
    assert hmac.require_touch(True) is hmac

    hotp = HotpSlotConfiguration(bytes(20))
    assert_type(hotp.append_cr(True), HotpSlotConfiguration)
    assert hotp.digits8(True) is hotp

    password = StaticPasswordSlotConfiguration(b"password")
    assert_type(password.pacing(True), StaticPasswordSlotConfiguration)
    assert password.use_numeric(True) is password

    otp = YubiOtpSlotConfiguration(b"public", bytes(6), bytes(16))
    assert_type(otp.fast_trigger(True), YubiOtpSlotConfiguration)
    assert otp.tabs(before=True).send_reference(True) is otp

    ticket = StaticTicketSlotConfiguration(b"public", bytes(6), bytes(16))
    assert_type(ticket.allow_update(True), StaticTicketSlotConfiguration)
    assert ticket.strong_password(upper_case=True).manual_update(True) is ticket

    update = UpdateConfiguration()
    assert_type(update.serial_usb_visible(True), UpdateConfiguration)
    assert update.tabs(before=True).delay(after_first=True) is update
