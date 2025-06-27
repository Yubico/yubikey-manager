# Copyright (c) 2020 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from time import sleep

from yubikit.core import PID, TRANSPORT, USB_INTERFACE
from yubikit.core.otp import CommandRejectedError, OtpProtocol

from ..base import YkmanDevice

YUBICO_VID = 0x1050

USAGE_FIDO = (0xF1D0, 1)
USAGE_OTP = (1, 6)


class OtpYubiKeyDevice(YkmanDevice):
    """YubiKey USB HID OTP device"""

    def __init__(self, path, pid, connection_cls):
        super().__init__(TRANSPORT.USB, path, PID(pid))
        self.path = path
        self._connection_cls = connection_cls

    def supports_connection(self, connection_type):
        return issubclass(self._connection_cls, connection_type)

    def open_connection(self, connection_type):
        assert isinstance(connection_type, type)  # noqa: S101
        if self.supports_connection(connection_type):
            conn = self._connection_cls(self.path)
            # If OTP-only, then it can't be reclaim
            if self.pid and self.pid.usb_interfaces != USB_INTERFACE.OTP:
                # Ensure we're not in reclaim
                proto = OtpProtocol(conn)
                for _ in range(6):
                    try:
                        # Read serial
                        proto.send_and_receive(0x10, b"")
                        break
                    except CommandRejectedError:
                        # In reclaim (maybe)
                        sleep(0.5)
            return conn

        return super().open_connection(connection_type)

    def _do_reinsert(self, reinsert_cb, event) -> None:
        raise NotImplementedError("Reinsert is not implemented on this platform")
