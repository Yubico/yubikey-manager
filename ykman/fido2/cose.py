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

from .utils import bytes2int, int2bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:  # EdDSA requires Cryptography >= 2.6.
    ed25519 = None


class CoseKey(dict):
    """A COSE formatted public key.

    :param _: The COSE key paramters.
    :cvar ALGORITHM: COSE algorithm identifier.
    """

    ALGORITHM = None

    def verify(self, message, signature):
        """Validates a digital signature over a given message.

        :param message: The message which was signed.
        :param signature: The signature to check.
        """
        raise NotImplementedError("Signature verification not supported.")

    @classmethod
    def from_cryptography_key(cls, public_key):
        """Converts a PublicKey object from Cryptography into a COSE key.

        :param public_key: Either an EC or RSA public key.
        :return: A CoseKey.
        """
        raise NotImplementedError("Creation from cryptography not supported.")

    @staticmethod
    def for_alg(alg):
        """Get a subclass of CoseKey corresponding to an algorithm identifier.

        :param alg: The COSE identifier of the algorithm.
        :return: A CoseKey.
        """
        if alg == EdDSA.ALGORITHM and ed25519 is None:
            # EdDSA requires Cryptography >= 2.6.
            return UnsupportedKey
        for cls in CoseKey.__subclasses__():
            if cls.ALGORITHM == alg:
                return cls
        return UnsupportedKey

    @staticmethod
    def for_name(name):
        """Get a subclass of CoseKey corresponding to an algorithm identifier.

        :param alg: The COSE identifier of the algorithm.
        :return: A CoseKey.
        """
        for cls in CoseKey.__subclasses__():
            if cls.__name__ == name:
                return cls
        return UnsupportedKey

    @staticmethod
    def parse(cose):
        """Create a CoseKey from a dict"""
        alg = cose.get(3)
        if not alg:
            raise ValueError("COSE alg identifier must be provided.")
        return CoseKey.for_alg(alg)(cose)

    @staticmethod
    def supported_algorithms():
        """Get a list of all supported algorithm identifiers"""
        if ed25519:
            algs = (ES256, EdDSA, PS256, RS256)
        else:
            algs = (ES256, PS256, RS256)
        return [cls.ALGORITHM for cls in algs]


class UnsupportedKey(CoseKey):
    """A COSE key with an unsupported algorithm."""


class ES256(CoseKey):
    ALGORITHM = -7
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        if self[-1] != 1:
            raise ValueError("Unsupported elliptic curve")
        ec.EllipticCurvePublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-3]), ec.SECP256R1()
        ).public_key(default_backend()).verify(
            signature, message, ec.ECDSA(self._HASH_ALG)
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        pn = public_key.public_numbers()
        return cls(
            {
                1: 2,
                3: cls.ALGORITHM,
                -1: 1,
                -2: int2bytes(pn.x, 32),
                -3: int2bytes(pn.y, 32),
            }
        )

    @classmethod
    def from_ctap1(cls, data):
        """Creates an ES256 key from a CTAP1 formatted public key byte string.

        :param data: A 65 byte SECP256R1 public key.
        :return: A ES256 key.
        """
        return cls({1: 2, 3: cls.ALGORITHM, -1: 1, -2: data[1:33], -3: data[33:65]})


class RS256(CoseKey):
    ALGORITHM = -257
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(signature, message, padding.PKCS1v15(), self._HASH_ALG)

    @classmethod
    def from_cryptography_key(cls, public_key):
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class PS256(CoseKey):
    ALGORITHM = -37
    _HASH_ALG = hashes.SHA256()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(self._HASH_ALG), salt_length=padding.PSS.MAX_LENGTH
            ),
            self._HASH_ALG,
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})


class EdDSA(CoseKey):
    ALGORITHM = -8

    def verify(self, message, signature):
        if self[-1] != 6:
            raise ValueError("Unsupported elliptic curve")
        ed25519.Ed25519PublicKey.from_public_bytes(self[-2]).verify(signature, message)

    @classmethod
    def from_cryptography_key(cls, public_key):
        return cls(
            {
                1: 1,
                3: cls.ALGORITHM,
                -1: 6,
                -2: public_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
            }
        )


class RS1(CoseKey):
    ALGORITHM = -65535
    _HASH_ALG = hashes.SHA1()

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(bytes2int(self[-2]), bytes2int(self[-1])).public_key(
            default_backend()
        ).verify(signature, message, padding.PKCS1v15(), self._HASH_ALG)

    @classmethod
    def from_cryptography_key(cls, public_key):
        pn = public_key.public_numbers()
        return cls({1: 3, 3: cls.ALGORITHM, -1: int2bytes(pn.n), -2: int2bytes(pn.e)})
