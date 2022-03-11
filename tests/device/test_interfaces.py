from ykman.device import connect_to_device
from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from . import condition


def try_connection(conn_type):
    with connect_to_device(None, [conn_type])[0]:
        return True


@condition.transport(TRANSPORT.USB)
def test_switch_interfaces(pid):
    if pid.supports_connection(FidoConnection):
        assert try_connection(FidoConnection)
    if pid.supports_connection(OtpConnection):
        assert try_connection(OtpConnection)
    if pid.supports_connection(FidoConnection):
        assert try_connection(FidoConnection)
    if pid.supports_connection(SmartCardConnection):
        assert try_connection(SmartCardConnection)
    if pid.supports_connection(OtpConnection):
        assert try_connection(OtpConnection)
    if pid.supports_connection(SmartCardConnection):
        assert try_connection(SmartCardConnection)
    if pid.supports_connection(FidoConnection):
        assert try_connection(FidoConnection)
