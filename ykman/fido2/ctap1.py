# Copyright (c) 2013 Yubico AB
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

from .hid import CTAPHID
from .utils import websafe_encode, websafe_decode, bytes2int, ByteBuffer
from .cose import ES256
from .attestation import FidoU2FAttestation
from enum import IntEnum, unique
from binascii import b2a_hex
import struct
import six


@unique
class APDU(IntEnum):
    """APDU response codes."""

    OK = 0x9000
    USE_NOT_SATISFIED = 0x6985
    WRONG_DATA = 0x6A80


class ApduError(Exception):
    """An Exception thrown when a response APDU doesn't have an OK (0x9000)
    status.

    :param code: APDU response code.
    :param data: APDU response body.

    """

    def __init__(self, code, data=b""):
        self.code = code
        self.data = data

    def __repr__(self):
        return "APDU error: 0x{:04X} {:d} bytes of data".format(
            self.code, len(self.data)
        )


class RegistrationData(bytes):
    """Binary response data for a CTAP1 registration.

    :param _: The binary contents of the response data.
    :ivar public_key: Binary representation of the credential public key.
    :ivar key_handle: Binary key handle of the credential.
    :ivar certificate: Attestation certificate of the authenticator, DER
        encoded.
    :ivar signature: Attestation signature.
    """

    def __init__(self, _):
        super(RegistrationData, self).__init__()

        if six.indexbytes(self, 0) != 0x05:
            raise ValueError("Reserved byte != 0x05")

        self.public_key = self[1:66]
        kh_len = six.indexbytes(self, 66)
        self.key_handle = self[67 : 67 + kh_len]

        cert_offs = 67 + kh_len
        cert_len = six.indexbytes(self, cert_offs + 1)
        if cert_len > 0x80:
            n_bytes = cert_len - 0x80
            cert_len = (
                bytes2int(self[cert_offs + 2 : cert_offs + 2 + n_bytes]) + n_bytes
            )
        cert_len += 2
        self.certificate = self[cert_offs : cert_offs + cert_len]
        self.signature = self[cert_offs + cert_len :]

    @property
    def b64(self):
        """Websafe base64 encoded string of the RegistrationData."""
        return websafe_encode(self)

    def verify(self, app_param, client_param):
        """Verify the included signature with regard to the given app and client
        params.

        :param app_param: SHA256 hash of the app ID used for the request.
        :param client_param: SHA256 hash of the ClientData used for the request.
        """
        FidoU2FAttestation.verify_signature(
            app_param,
            client_param,
            self.key_handle,
            self.public_key,
            self.certificate,
            self.signature,
        )

    def __repr__(self):
        return (
            "RegistrationData(public_key: h'%s', key_handle: h'%s', "
            "certificate: h'%s', signature: h'%s')"
        ) % tuple(
            b2a_hex(x).decode()
            for x in (
                self.public_key,
                self.key_handle,
                self.certificate,
                self.signature,
            )
        )

    def __str__(self):
        return "%r" % self

    @classmethod
    def from_b64(cls, data):
        """Parse a RegistrationData from a websafe base64 encoded string.

        :param data: Websafe base64 encoded string.
        :return: The decoded and parsed RegistrationData.
        """
        return cls(websafe_decode(data))


class SignatureData(bytes):
    """Binary response data for a CTAP1 authentication.

    :param _: The binary contents of the response data.
    :ivar user_presence: User presence byte.
    :ivar counter: Signature counter.
    :ivar signature: Cryptographic signature.
    """

    def __init__(self, _):
        super(SignatureData, self).__init__()

        reader = ByteBuffer(self)
        self.user_presence = reader.unpack("B")
        self.counter = reader.unpack(">I")
        self.signature = reader.read()

    @property
    def b64(self):
        """str: Websafe base64 encoded string of the SignatureData."""
        return websafe_encode(self)

    def verify(self, app_param, client_param, public_key):
        """Verify the included signature with regard to the given app and client
        params, using the given public key.

        :param app_param: SHA256 hash of the app ID used for the request.
        :param client_param: SHA256 hash of the ClientData used for the request.
        :param public_key: Binary representation of the credential public key.
        """
        m = app_param + self[:5] + client_param
        ES256.from_ctap1(public_key).verify(m, self.signature)

    def __repr__(self):
        return (
            "SignatureData(user_presence: 0x%02x, counter: %d, " "signature: h'%s'"
        ) % (self.user_presence, self.counter, b2a_hex(self.signature))

    def __str__(self):
        return "%r" % self

    @classmethod
    def from_b64(cls, data):
        """Parse a SignatureData from a websafe base64 encoded string.

        :param data: Websafe base64 encoded string.
        :return: The decoded and parsed SignatureData.
        """
        return cls(websafe_decode(data))


class CTAP1(object):
    """Implementation of the CTAP1 specification.

    :param device: A CtapHidDevice handle supporting CTAP1.
    """

    @unique
    class INS(IntEnum):
        REGISTER = 0x01
        AUTHENTICATE = 0x02
        VERSION = 0x03

    def __init__(self, device):
        self.device = device

    def send_apdu(self, cla=0, ins=0, p1=0, p2=0, data=b""):
        """Packs and sends an APDU for use in CTAP1 commands.
        This is a low-level method mainly used internally. Avoid calling it
        directly if possible, and use the get_version, register, and
        authenticate methods if possible instead.

        :param cla: The CLA parameter of the request.
        :param ins: The INS parameter of the request.
        :param p1: The P1 parameter of the request.
        :param p2: The P2 parameter of the request.
        :param data: The body of the request.
        :return: The response APDU data of a successful request.
        :raise: ApduError
        """
        size = len(data)
        size_h = size >> 16 & 0xFF
        size_l = size & 0xFFFF
        apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, size_h, size_l) + data + b"\0\0"

        response = self.device.call(CTAPHID.MSG, apdu)
        status = struct.unpack(">H", response[-2:])[0]
        data = response[:-2]
        if status != APDU.OK:
            raise ApduError(status, data)
        return data

    def get_version(self):
        """Get the U2F version implemented by the authenticator.
        The only version specified is "U2F_V2".

        :return: A U2F version string.
        """
        return self.send_apdu(ins=CTAP1.INS.VERSION).decode()

    def register(self, client_param, app_param):
        """Register a new U2F credential.

        :param client_param: SHA256 hash of the ClientData used for the request.
        :param app_param: SHA256 hash of the app ID used for the request.
        :return: The registration response from the authenticator.
        """
        data = client_param + app_param
        response = self.send_apdu(ins=CTAP1.INS.REGISTER, data=data)
        return RegistrationData(response)

    def authenticate(self, client_param, app_param, key_handle, check_only=False):
        """Authenticate a previously registered credential.

        :param client_param: SHA256 hash of the ClientData used for the request.
        :param app_param: SHA256 hash of the app ID used for the request.
        :param key_handle: The binary key handle of the credential.
        :param check_only: True to send a "check-only" request, which is used to
            determine if a key handle is known.
        :return: The authentication response from the authenticator.
        """
        data = (
            client_param + app_param + struct.pack(">B", len(key_handle)) + key_handle
        )
        p1 = 0x07 if check_only else 0x03
        response = self.send_apdu(ins=CTAP1.INS.AUTHENTICATE, p1=p1, data=data)
        return SignatureData(response)
