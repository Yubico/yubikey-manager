# Copyright (c) 2019 Yubico AB
# Copyright (c) 2019 Oleg Moiseenko
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

from __future__ import absolute_import, unicode_literals

from .ctap import CtapDevice, CtapError, STATUS
from .hid import CAPABILITY, CTAPHID
from .pcsc import PCSCDevice
from smartcard.Exceptions import CardConnectionException
from threading import Event
import struct
import six


AID_FIDO = b"\xa0\x00\x00\x06\x47\x2f\x00\x01"
SW_SUCCESS = (0x90, 0x00)
SW_UPDATE = (0x91, 0x00)
SW1_MORE_DATA = 0x61


class CardSelectException(Exception):
    """can't select u2f/fido2 application on the card"""

    pass


class CtapNfcDevice(CtapDevice):
    """
    CtapDevice implementation using the pcsc NFC transport.
    """

    def __init__(self, dev):
        self._dev = dev
        self._dev.connect()
        self._capabilities = 0

        result, sw1, sw2 = self._dev.select_applet(AID_FIDO)
        if (sw1, sw2) != SW_SUCCESS:
            raise CardSelectException("Select error")

        if result == b"U2F_V2":
            self._capabilities |= CAPABILITY.NMSG
        try:  # Probe for CTAP2 by calling GET_INFO
            self.call(CTAPHID.CBOR, b"\x04")
            self._capabilities |= CAPABILITY.CBOR
        except CtapError:
            pass

    @property
    def pcsc_device(self):
        return self._dev

    def __repr__(self):
        return "CtapNfcDevice(%s)" % self._dev.reader.name

    @property
    def version(self):
        """CTAP NFC protocol version.
        :rtype: int
        """
        return 2 if self._capabilities & CAPABILITY.CBOR else 1

    @property
    def capabilities(self):
        """Capabilities supported by the device."""
        return self._capabilities

    def _chain_apdus(self, cla, ins, p1, p2, data=b""):
        while len(data) > 250:
            to_send, data = data[:250], data[250:]
            header = struct.pack("!BBBBB", 0x90, ins, p1, p2, len(to_send))
            resp, sw1, sw2 = self._dev.apdu_exchange(header + to_send)
            if (sw1, sw2) != SW_SUCCESS:
                return resp, sw1, sw2
        apdu = struct.pack("!BBBB", cla, ins, p1, p2)
        if data:
            apdu += struct.pack("!B", len(data)) + data
        resp, sw1, sw2 = self._dev.apdu_exchange(apdu + b"\x00")
        while sw1 == SW1_MORE_DATA:
            apdu = b"\x00\xc0\x00\x00" + struct.pack("!B", sw2)  # sw2 == le
            lres, sw1, sw2 = self._dev.apdu_exchange(apdu)
            resp += lres
        return resp, sw1, sw2

    def _call_apdu(self, apdu):
        if len(apdu) >= 7 and six.indexbytes(apdu, 4) == 0:
            # Extended APDU
            data_len = struct.unpack("!H", apdu[5:7])[0]
            data = apdu[7 : 7 + data_len]
        else:
            # Short APDU
            data_len = six.indexbytes(apdu, 4)
            data = apdu[5 : 5 + data_len]
        (cla, ins, p1, p2) = six.iterbytes(apdu[:4])

        resp, sw1, sw2 = self._chain_apdus(cla, ins, p1, p2, data)
        return resp + struct.pack("!BB", sw1, sw2)

    def _call_cbor(self, data=b"", event=None, on_keepalive=None):
        event = event or Event()
        # NFCCTAP_MSG
        resp, sw1, sw2 = self._chain_apdus(0x80, 0x10, 0x80, 0x00, data)
        last_ka = None

        while not event.is_set():
            while (sw1, sw2) == SW_UPDATE:
                ka_status = six.indexbytes(resp, 0)
                if on_keepalive and last_ka != ka_status:
                    try:
                        ka_status = STATUS(ka_status)
                    except ValueError:
                        pass  # Unknown status value
                    last_ka = ka_status
                    on_keepalive(ka_status)

                # NFCCTAP_GETRESPONSE
                resp, sw1, sw2 = self._chain_apdus(0x80, 0x11, 0x00, 0x00, b"")

            if (sw1, sw2) != SW_SUCCESS:
                raise CtapError(CtapError.ERR.OTHER)  # TODO: Map from SW error

            return resp

        raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        if cmd == CTAPHID.MSG:
            return self._call_apdu(data)
        elif cmd == CTAPHID.CBOR:
            return self._call_cbor(data, event, on_keepalive)
        else:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)

    @classmethod  # selector='CL'
    def list_devices(cls, selector="", pcsc_device=PCSCDevice):
        """
        Returns list of readers in the system. Iterator.
        :param selector:
        :param pcsc_device: device to work with.  PCSCDevice by default.
        :return: iterator. next reader
        """
        for d in pcsc_device.list_devices(selector):
            try:
                yield cls(d)
            except CardConnectionException:
                pass
