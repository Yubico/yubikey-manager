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

"""Various utility functions.

This module contains various functions used throughout the rest of the project.
"""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, hashes
from binascii import b2a_hex
from io import BytesIO
import six
import struct

__all__ = [
    "websafe_encode",
    "websafe_decode",
    "sha256",
    "hmac_sha256",
    "bytes2int",
    "int2bytes",
]


def sha256(data):
    """Produces a SHA256 hash of the input.

    :param data: The input data to hash.
    :return: The resulting hash.
    """
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()


def hmac_sha256(key, data):
    """Performs an HMAC-SHA256 operation on the given data, using the given key.

    :param key: The key to use.
    :param data: The input data to hash.
    :return: The resulting hash.
    """
    h = hmac.HMAC(key, hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()


def bytes2int(value):
    """Parses an arbitrarily sized integer from a byte string.

    :param value: A byte string encoding a big endian unsigned integer.
    :return: The parsed int.
    """
    return int(b2a_hex(value), 16)


def int2bytes(value, minlen=-1):
    """Encodes an int as a byte string.

    :param value: The integer value to encode.
    :param minlen: An optional minimum length for the resulting byte string.
    :return: The value encoded as a big endian byte string.
    """
    ba = []
    while value > 0xFF:
        ba.append(0xFF & value)
        value >>= 8
    ba.append(value)
    ba.extend([0] * (minlen - len(ba)))
    return bytes(bytearray(reversed(ba)))


def websafe_decode(data):
    """Decodes a websafe-base64 encoded string (bytes or str).
    See: "Base 64 Encoding with URL and Filename Safe Alphabet" from Section 5
    in RFC4648 without padding.

    :param data: The input to decode.
    :return: The decoded bytes.
    """
    if isinstance(data, six.text_type):
        data = data.encode("ascii")
    data += b"=" * (-len(data) % 4)
    return urlsafe_b64decode(data)


def websafe_encode(data):
    """Encodes a byte string into websafe-base64 encoding.

    :param data: The input to encode.
    :return: The encoded string.
    """
    return urlsafe_b64encode(data).replace(b"=", b"").decode("ascii")


class ByteBuffer(BytesIO):
    """BytesIO-like object with the ability to unpack values."""

    def unpack(self, fmt):
        """Reads and unpacks a value from the buffer.

        :param fmt: A struct format string yielding a single value.
        :return: The unpacked value.
        """
        s = struct.Struct(fmt)
        return s.unpack(self.read(s.size))[0]

    def read(self, size=-1):
        """Like BytesIO.read(), but checks the number of bytes read and raises an error
        if fewer bytes were read than expected.
        """
        data = super(ByteBuffer, self).read(size)
        if size > 0 and len(data) != size:
            raise ValueError(
                "Not enough data to read (need: %d, had: %d)." % (size, len(data))
            )
        return data
