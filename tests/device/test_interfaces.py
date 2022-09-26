from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from . import condition


def try_connection(device, conn_type):
    with device.open_connection(conn_type):
        return True


@condition.transport(TRANSPORT.USB)
def test_switch_interfaces(device):
    for conn_type in (
        FidoConnection,
        OtpConnection,
        FidoConnection,
        SmartCardConnection,
        OtpConnection,
        SmartCardConnection,
        FidoConnection,
    ):
        if device.pid.supports_connection(conn_type):
            assert try_connection(device, conn_type)
