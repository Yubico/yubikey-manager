from ykman.device import connect_to_device
from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import USB_INTERFACE
from . import condition


def try_connection(conn_type):
    with connect_to_device(None, [conn_type])[0]:
        return True


@condition.transport(TRANSPORT.USB)
def test_switch_interfaces(pid):
    interfaces = pid.get_interfaces()
    if USB_INTERFACE.FIDO in interfaces:
        assert try_connection(FidoConnection)
    if USB_INTERFACE.OTP in interfaces:
        assert try_connection(OtpConnection)
    if USB_INTERFACE.FIDO in interfaces:
        assert try_connection(FidoConnection)
    if USB_INTERFACE.CCID in interfaces:
        assert try_connection(SmartCardConnection)
    if USB_INTERFACE.OTP in interfaces:
        assert try_connection(OtpConnection)
    if USB_INTERFACE.CCID in interfaces:
        assert try_connection(SmartCardConnection)
    if USB_INTERFACE.FIDO in interfaces:
        assert try_connection(FidoConnection)
