# Copyright (c) 2018 Yubico AB
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

from .ctap2 import PinProtocolV1
from .utils import hmac_sha256
import abc


class Extension(abc.ABC):
    """
    Base class for CTAP2 extensions.
    """

    NAME = None

    def results_for(self, auth_data):
        """
        Get the parsed extension results from an AuthenticatorData object.
        """
        data = auth_data.extensions.get(self.NAME)
        if auth_data.is_attested():
            return self.create_result(data)
        else:
            return self.get_result(data)

    def create_dict(self, *args, **kwargs):
        """
        Return extension dict for use with calls to make_credential.
        """
        return {self.NAME: self.create_data(*args, **kwargs)}

    def get_dict(self, *args, **kwargs):
        """
        Return extension dict for use with calls to get_assertion.
        """
        return {self.NAME: self.get_data(*args, **kwargs)}

    @abc.abstractmethod
    def create_data(self, *args, **kwargs):
        """
        Return extension data value for use with calls to make_credential.
        """

    @abc.abstractmethod
    def create_result(self, data):
        """
        Process and return extension result from call to make_credential.
        """

    @abc.abstractmethod
    def get_data(self, *args, **kwargs):
        """
        Return extension data value for use with calls to get_assertion.
        """

    @abc.abstractmethod
    def get_result(self, data):
        """
        Process and return extension result from call to get_assertion.
        """


class HmacSecretExtension(Extension):
    """
    Implements the hmac-secret CTAP2 extension.
    """

    NAME = "hmac-secret"
    SALT_LEN = 32

    def __init__(self, ctap):
        self._pin_protocol = PinProtocolV1(ctap)

    def create_data(self):
        return True

    def create_result(self, data):
        if data is not True:
            raise ValueError("hmac-secret extension not supported")

    def get_data(self, salt1, salt2=b""):
        if len(salt1) != self.SALT_LEN:
            raise ValueError("Wrong length for salt1")
        if salt2 and len(salt2) != self.SALT_LEN:
            raise ValueError("Wrong length for salt2")

        key_agreement, shared_secret = self._pin_protocol.get_shared_secret()
        self._agreement = key_agreement
        self._secret = shared_secret

        enc = self._pin_protocol._get_cipher(shared_secret).encryptor()
        salt_enc = enc.update(salt1) + enc.update(salt2) + enc.finalize()

        return {
            1: key_agreement,
            2: salt_enc,
            3: hmac_sha256(shared_secret, salt_enc)[:16],
        }

    def get_result(self, data):
        dec = self._pin_protocol._get_cipher(self._secret).decryptor()
        salt = dec.update(data) + dec.finalize()
        return (
            salt[: HmacSecretExtension.SALT_LEN],
            salt[HmacSecretExtension.SALT_LEN :],
        )
