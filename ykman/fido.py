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

import time
import struct
import logging
from yubikit.core.fido import FidoConnection
from fido2.hid import CTAPHID
from fido2.ctap1 import CTAP1, ApduError
from fido2.ctap2 import CTAP2, ClientPin, CredentialManagement
from threading import Timer, Event
from enum import IntEnum, unique


logger = logging.getLogger(__name__)

SW_CONDITIONS_NOT_SATISFIED = 0x6985


@unique
class FIPS_U2F_CMD(IntEnum):
    ECHO = CTAPHID.VENDOR_FIRST
    WRITE_CONFIG = CTAPHID.VENDOR_FIRST + 1
    APP_VERSION = CTAPHID.VENDOR_FIRST + 2
    VERIFY_PIN = CTAPHID.VENDOR_FIRST + 3
    SET_PIN = CTAPHID.VENDOR_FIRST + 4
    RESET = CTAPHID.VENDOR_FIRST + 5
    VERIFY_FIPS_MODE = CTAPHID.VENDOR_FIRST + 6


class ResidentCredential(object):
    def __init__(self, raw_credential, raw_rp):
        self._raw_credential = raw_credential
        self._raw_rp = raw_rp

    @property
    def credential_id(self):
        return self._raw_credential[CredentialManagement.RESULT.CREDENTIAL_ID]

    @property
    def rp_id(self):
        return self._raw_rp[CredentialManagement.RESULT.RP]["id"]

    @property
    def user_name(self):
        return self._raw_credential[CredentialManagement.RESULT.USER]["name"]

    @property
    def user_id(self):
        return self._raw_credential[CredentialManagement.RESULT.USER]["id"]


class Fido2Controller(object):
    def __init__(self, ctap_device):
        self.ctap = CTAP2(ctap_device)
        self.pin = ClientPin(self.ctap)
        self._info = self.ctap.get_info()
        self._pin = self._info.options["clientPin"]

    @property
    def has_pin(self):
        return self._pin

    def get_resident_credentials(self, pin):
        _credman = CredentialManagement(
            self.ctap,
            self.pin.protocol,
            self.pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT),
        )

        for rp in _credman.enumerate_rps():
            for cred in _credman.enumerate_creds(
                rp[CredentialManagement.RESULT.RP_ID_HASH]
            ):
                yield ResidentCredential(cred, rp)

    def delete_resident_credential(self, credential_id, pin):
        _credman = CredentialManagement(
            self.ctap,
            self.pin.protocol,
            self.pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT),
        )

        for cred in self.get_resident_credentials(pin):
            if credential_id == cred.credential_id:
                _credman.delete_cred(credential_id)

    def get_pin_retries(self):
        return self.pin.get_pin_retries()[0]

    def set_pin(self, pin):
        self.pin.set_pin(pin)
        self._pin = True

    def change_pin(self, old_pin, new_pin):
        self.pin.change_pin(old_pin, new_pin)

    def reset(self, touch_callback=None):
        event = Event()

        def on_keepalive(status):
            if not hasattr(on_keepalive, "prompted") and status == 2:
                touch_callback()
                on_keepalive.prompted = True

        self.ctap.reset(event, on_keepalive)
        self._pin = False

    @property
    def is_fips(self):
        return False


def is_in_fips_mode(fido_connection: FidoConnection) -> bool:
    try:
        ctap = CTAP1(fido_connection)
        ctap.send_apdu(ins=FIPS_U2F_CMD.VERIFY_FIPS_MODE)
        return True
    except ApduError:
        return False


class FipsU2fController(object):
    def __init__(self, ctap_device):
        self.ctap = CTAP1(ctap_device)

    @property
    def has_pin(self):
        # We don't know, but the change and set commands are the same here.
        return True

    def set_pin(self, pin):
        raise NotImplementedError("Use the change_pin method instead.")

    def change_pin(self, old_pin, new_pin):
        new_length = len(new_pin)

        old_pin = old_pin.encode()
        new_pin = new_pin.encode()

        data = struct.pack("B", new_length) + old_pin + new_pin

        self.ctap.send_apdu(ins=FIPS_U2F_CMD.SET_PIN, data=data)
        return True

    def verify_pin(self, pin):
        self.ctap.send_apdu(ins=FIPS_U2F_CMD.VERIFY_PIN, data=pin.encode())

    def reset(self, touch_callback=None):
        if touch_callback:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        try:
            while True:
                try:
                    self.ctap.send_apdu(ins=FIPS_U2F_CMD.RESET)
                    self._pin = False
                    return True
                except ApduError as e:
                    if e.code == SW_CONDITIONS_NOT_SATISFIED:
                        time.sleep(0.5)
                    else:
                        raise e

        finally:
            if touch_callback:
                touch_timer.cancel()

    @property
    def is_fips(self):
        return True

    @property
    def is_in_fips_mode(self):
        try:
            self.ctap.send_apdu(ins=FIPS_U2F_CMD.VERIFY_FIPS_MODE)
            return True
        except ApduError:
            return False
