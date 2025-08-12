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

import logging
import struct
from threading import Event
from typing import Callable, Iterator

from fido2.ctap import STATUS, CtapDevice, CtapError
from fido2.hid import CAPABILITY, CTAPHID

from yubikit.core import Version
from yubikit.core.smartcard import (
    AID,
    ApduError,
    SmartCardConnection,
    SmartCardProtocol,
)
from yubikit.core.smartcard.scp import ScpKeyParams

from . import USB_INTERFACE, Connection

logger = logging.getLogger(__name__)


# Make CtapDevice a Connection
FidoConnection = CtapDevice
FidoConnection.usb_interface = USB_INTERFACE.FIDO  # type: ignore[attr-defined]
Connection.register(FidoConnection)


# Use SmartCardConnection for FIDO access, allowing usage of SCP
class SmartCardCtapDevice(CtapDevice, Connection):
    usb_interface = USB_INTERFACE.CCID

    def __init__(
        self,
        connection: SmartCardConnection,
        scp_key_params: ScpKeyParams | None = None,
    ):
        self._capabilities = CAPABILITY(0)

        self.protocol = SmartCardProtocol(connection)
        resp = self.protocol.select(AID.FIDO)
        if resp == b"U2F_V2":
            self._capabilities |= CAPABILITY.NMSG

        if scp_key_params:
            # We can at least raise the configuration level to 5.3.0,
            # since SCP is not available before then
            self.protocol.configure(Version(5, 3, 0))
            self.protocol.init_scp(scp_key_params)

        try:  # Probe for CTAP2 by calling GET_INFO
            self.call(CTAPHID.CBOR, b"\x04")
            self._capabilities |= CAPABILITY.CBOR
        except CtapError:
            if not self._capabilities:
                raise ValueError("Unsupported device")

        logger.debug("FIDO session initialized")

    @property
    def capabilities(self) -> CAPABILITY:
        return self._capabilities

    def close(self) -> None:
        self.protocol.close()

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        match cmd:
            case CTAPHID.MSG:
                cla, ins, p1, p2 = data[:4]
                if data[4] == 0:
                    ln = struct.unpack(">H", data[5:7])[0]
                    data = data[7 : 7 + ln]
                else:
                    data = data[5 : 5 + data[4]]
            case CTAPHID.CBOR:
                # NFCCTAP_MSG
                cla, ins, p1, p2 = 0x80, 0x10, 0x80, 0x00
            case _:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)

        event = event or Event()
        last_ka = None

        try:
            while True:
                try:
                    return self.protocol.send_apdu(cla, ins, p1, p2, data)
                except ApduError as e:
                    if e.sw == 0x9100:
                        ins, p1 = 0x11, 0x00  # NFCCTAP_GETRESPONSE
                        ka_status = STATUS(e.data[0])
                        if on_keepalive and last_ka != ka_status:
                            last_ka = ka_status
                            on_keepalive(ka_status)
                        if event.wait(0.1):
                            p1 = 0x11  # cancel
                        continue
                    raise CtapError(CtapError.ERR.OTHER)  # TODO: Map from SW error
        except KeyboardInterrupt:
            if ins == 0x11:
                logger.debug("Keyboard interrupt, cancelling...")
                self.protocol.send_apdu(cla, ins, 0x11, p2)
            raise

    @classmethod
    def list_devices(cls) -> Iterator[CtapDevice]:
        return iter([])  # Not implemented
