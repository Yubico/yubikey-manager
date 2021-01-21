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

from __future__ import absolute_import

from enum import IntEnum, unique
import abc


@unique
class STATUS(IntEnum):
    PROCESSING = 1
    UPNEEDED = 2


class CtapDevice(abc.ABC):
    """
    CTAP-capable device. Subclasses of this should implement call, as well as
    list_devices, which should return a generator over discoverable devices.
    """

    @abc.abstractmethod
    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        """Sends a command to the authenticator, and reads the response.

        :param cmd: The integer value of the command.
        :param data: The payload of the command.
        :param event: An optional threading.Event which can be used to cancel
            the invocation.
        :param on_keepalive: An optional callback to handle keep-alive messages
            from the authenticator. The function is only called once for
            consecutive keep-alive messages with the same status.
        :return: The response from the authenticator.
        """

    def close(self):
        """Close the device, releasing any held resources."""

    @classmethod
    @abc.abstractmethod
    def list_devices(cls):
        """Generates instances of cls for discoverable devices."""


class CtapError(Exception):
    @unique
    class ERR(IntEnum):
        SUCCESS = 0x00
        INVALID_COMMAND = 0x01
        INVALID_PARAMETER = 0x02
        INVALID_LENGTH = 0x03
        INVALID_SEQ = 0x04
        TIMEOUT = 0x05
        CHANNEL_BUSY = 0x06
        LOCK_REQUIRED = 0x0A
        INVALID_CHANNEL = 0x0B
        CBOR_UNEXPECTED_TYPE = 0x11
        INVALID_CBOR = 0x12
        MISSING_PARAMETER = 0x14
        LIMIT_EXCEEDED = 0x15
        UNSUPPORTED_EXTENSION = 0x16
        CREDENTIAL_EXCLUDED = 0x19
        PROCESSING = 0x21
        INVALID_CREDENTIAL = 0x22
        USER_ACTION_PENDING = 0x23
        OPERATION_PENDING = 0x24
        NO_OPERATIONS = 0x25
        UNSUPPORTED_ALGORITHM = 0x26
        OPERATION_DENIED = 0x27
        KEY_STORE_FULL = 0x28
        NOT_BUSY = 0x29
        NO_OPERATION_PENDING = 0x2A
        UNSUPPORTED_OPTION = 0x2B
        INVALID_OPTION = 0x2C
        KEEPALIVE_CANCEL = 0x2D
        NO_CREDENTIALS = 0x2E
        USER_ACTION_TIMEOUT = 0x2F
        NOT_ALLOWED = 0x30
        PIN_INVALID = 0x31
        PIN_BLOCKED = 0x32
        PIN_AUTH_INVALID = 0x33
        PIN_AUTH_BLOCKED = 0x34
        PIN_NOT_SET = 0x35
        PIN_REQUIRED = 0x36
        PIN_POLICY_VIOLATION = 0x37
        PIN_TOKEN_EXPIRED = 0x38
        REQUEST_TOO_LARGE = 0x39
        ACTION_TIMEOUT = 0x3A
        UP_REQUIRED = 0x3B
        OTHER = 0x7F
        SPEC_LAST = 0xDF
        EXTENSION_FIRST = 0xE0
        EXTENSION_LAST = 0xEF
        VENDOR_FIRST = 0xF0
        VENDOR_LAST = 0xFF

        def __str__(self):
            return "0x%02X - %s" % (self.value, self.name)

    def __init__(self, code):
        try:
            code = CtapError.ERR(code)
            message = "CTAP error: %s" % code
        except ValueError:
            message = "CTAP error: 0x%02X" % code
        self.code = code
        super(CtapError, self).__init__(message)
