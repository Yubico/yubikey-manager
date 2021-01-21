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

from __future__ import absolute_import, unicode_literals, division

from .hid import STATUS
from .ctap import CtapError
from .ctap1 import CTAP1, APDU, ApduError
from .ctap2 import CTAP2, PinProtocolV1, AttestationObject, AssertionResponse, Info
from .webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)
from .cose import ES256
from .rpid import verify_rp_id, verify_app_id
from .utils import sha256, hmac_sha256, websafe_decode, websafe_encode
from enum import Enum, IntEnum, unique
from threading import Timer, Event

import json
import six
import platform


class ClientData(bytes):
    def __init__(self, _):
        super(ClientData, self).__init__()
        self.data = json.loads(self.decode())

    def get(self, key):
        return self.data[key]

    @property
    def challenge(self):
        return websafe_decode(self.get("challenge"))

    @property
    def b64(self):
        return websafe_encode(self)

    @property
    def hash(self):
        return sha256(self)

    @classmethod
    def build(cls, **kwargs):
        return cls(json.dumps(kwargs).encode())

    @classmethod
    def from_b64(cls, data):
        return cls(websafe_decode(data))

    def __repr__(self):
        return self.decode()

    def __str__(self):
        return self.decode()


class ClientError(Exception):
    @unique
    class ERR(IntEnum):
        OTHER_ERROR = 1
        BAD_REQUEST = 2
        CONFIGURATION_UNSUPPORTED = 3
        DEVICE_INELIGIBLE = 4
        TIMEOUT = 5

        def __call__(self, cause=None):
            return ClientError(self, cause)

    def __init__(self, code, cause=None):
        self.code = ClientError.ERR(code)
        self.cause = cause

    def __repr__(self):
        r = "Client error: {0} - {0.name}".format(self.code)
        if self.cause:
            r += ". Caused by {}".format(self.cause)
        return r


def _ctap2client_err(e):
    if e.code in [CtapError.ERR.CREDENTIAL_EXCLUDED, CtapError.ERR.NO_CREDENTIALS]:
        ce = ClientError.ERR.DEVICE_INELIGIBLE
    elif e.code in [
        CtapError.ERR.KEEPALIVE_CANCEL,
        CtapError.ERR.ACTION_TIMEOUT,
        CtapError.ERR.USER_ACTION_TIMEOUT,
    ]:
        ce = ClientError.ERR.TIMEOUT
    elif e.code in [
        CtapError.ERR.UNSUPPORTED_ALGORITHM,
        CtapError.ERR.UNSUPPORTED_OPTION,
        CtapError.ERR.UNSUPPORTED_EXTENSION,
        CtapError.ERR.KEY_STORE_FULL,
    ]:
        ce = ClientError.ERR.CONFIGURATION_UNSUPPORTED
    elif e.code in [
        CtapError.ERR.INVALID_COMMAND,
        CtapError.ERR.CBOR_UNEXPECTED_TYPE,
        CtapError.ERR.INVALID_CBOR,
        CtapError.ERR.MISSING_PARAMETER,
        CtapError.ERR.INVALID_OPTION,
        CtapError.ERR.PIN_REQUIRED,
        CtapError.ERR.PIN_INVALID,
        CtapError.ERR.PIN_BLOCKED,
        CtapError.ERR.PIN_NOT_SET,
        CtapError.ERR.PIN_POLICY_VIOLATION,
        CtapError.ERR.PIN_TOKEN_EXPIRED,
        CtapError.ERR.PIN_AUTH_INVALID,
        CtapError.ERR.PIN_AUTH_BLOCKED,
        CtapError.ERR.REQUEST_TOO_LARGE,
        CtapError.ERR.OPERATION_DENIED,
    ]:
        ce = ClientError.ERR.BAD_REQUEST
    else:
        ce = ClientError.ERR.OTHER_ERROR

    return ce(e)


def _call_polling(poll_delay, event, on_keepalive, func, *args, **kwargs):
    event = event or Event()
    while not event.is_set():
        try:
            return func(*args, **kwargs)
        except ApduError as e:
            if e.code == APDU.USE_NOT_SATISFIED:
                if on_keepalive:
                    on_keepalive(STATUS.UPNEEDED)
                    on_keepalive = None
                event.wait(poll_delay)
            else:
                raise ClientError.ERR.OTHER_ERROR(e)
        except CtapError as e:
            raise _ctap2client_err(e)
    raise ClientError.ERR.TIMEOUT()


@unique
class U2F_TYPE(six.text_type, Enum):
    REGISTER = "navigator.id.finishEnrollment"
    SIGN = "navigator.id.getAssertion"


class U2fClient(object):
    """U2F-like client implementation.

    The client allows registration and authentication of U2F credentials against
    an Authenticator using CTAP 1. Prefer using Fido2Client if possible.

    :param device: CtapDevice to use.
    :param str origin: The origin to use.
    :param verify: Function to verify an APP ID for a given origin.
    """

    def __init__(self, device, origin, verify=verify_app_id):
        self.poll_delay = 0.25
        self.ctap = CTAP1(device)
        self.origin = origin
        self._verify = verify

    def _verify_app_id(self, app_id):
        try:
            if self._verify(app_id, self.origin):
                return
        except Exception:
            pass  # Fall through to ClientError
        raise ClientError.ERR.BAD_REQUEST()

    def register(
        self, app_id, register_requests, registered_keys, event=None, on_keepalive=None
    ):
        self._verify_app_id(app_id)

        version = self.ctap.get_version()
        dummy_param = b"\0" * 32
        for key in registered_keys:
            if key["version"] != version:
                continue
            key_app_id = key.get("appId", app_id)
            app_param = sha256(key_app_id.encode())
            self._verify_app_id(key_app_id)
            key_handle = websafe_decode(key["keyHandle"])
            try:
                self.ctap.authenticate(dummy_param, app_param, key_handle, True)
                raise ClientError.ERR.DEVICE_INELIGIBLE()  # Bad response
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    raise ClientError.ERR.DEVICE_INELIGIBLE()
            except CtapError as e:
                raise _ctap2client_err(e)

        for request in register_requests:
            if request["version"] == version:
                challenge = request["challenge"]
                break
        else:
            raise ClientError.ERR.DEVICE_INELIGIBLE()

        client_data = ClientData.build(
            typ=U2F_TYPE.REGISTER, challenge=challenge, origin=self.origin
        )
        app_param = sha256(app_id.encode())

        reg_data = _call_polling(
            self.poll_delay,
            event,
            on_keepalive,
            self.ctap.register,
            client_data.hash,
            app_param,
        )

        return {"registrationData": reg_data.b64, "clientData": client_data.b64}

    def sign(self, app_id, challenge, registered_keys, event=None, on_keepalive=None):
        client_data = ClientData.build(
            typ=U2F_TYPE.SIGN, challenge=challenge, origin=self.origin
        )

        version = self.ctap.get_version()
        for key in registered_keys:
            if key["version"] == version:
                key_app_id = key.get("appId", app_id)
                self._verify_app_id(key_app_id)
                key_handle = websafe_decode(key["keyHandle"])
                app_param = sha256(key_app_id.encode())
                try:
                    signature_data = _call_polling(
                        self.poll_delay,
                        event,
                        on_keepalive,
                        self.ctap.authenticate,
                        client_data.hash,
                        app_param,
                        key_handle,
                    )
                    break
                except ClientError:
                    pass  # Ignore and try next key
        else:
            raise ClientError.ERR.DEVICE_INELIGIBLE()

        return {
            "clientData": client_data.b64,
            "signatureData": signature_data.b64,
            "keyHandle": key["keyHandle"],
        }


@unique
class WEBAUTHN_TYPE(six.text_type, Enum):
    MAKE_CREDENTIAL = "webauthn.create"
    GET_ASSERTION = "webauthn.get"


class _BaseClient(object):
    def __init__(self, origin, verify):
        self.origin = origin
        self._verify = verify

    def _verify_rp_id(self, rp_id):
        try:
            if self._verify(rp_id, self.origin):
                return
        except Exception:
            pass  # Fall through to ClientError
        raise ClientError.ERR.BAD_REQUEST()

    def _build_client_data(self, typ, challenge, extensions={}):
        return ClientData.build(
            type=typ,
            origin=self.origin,
            challenge=websafe_encode(challenge),
            clientExtensions=extensions,
        )


_CTAP1_INFO = Info.create(["U2F_V2"])


class Fido2Client(_BaseClient):
    """WebAuthn-like client implementation.

    The client allows registration and authentication of WebAuthn credentials against
    an Authenticator using CTAP (1 or 2).

    :param device: CtapDevice to use.
    :param str origin: The origin to use.
    :param verify: Function to verify an RP ID for a given origin.
    """

    def __init__(self, device, origin, verify=verify_rp_id):
        super(Fido2Client, self).__init__(origin, verify)

        self.ctap1_poll_delay = 0.25
        try:
            self.ctap2 = CTAP2(device)
            self.info = self.ctap2.get_info()
            if PinProtocolV1.VERSION in self.info.pin_protocols:
                self.pin_protocol = PinProtocolV1(self.ctap2)
            else:
                self.pin_protocol = None
            self._do_make_credential = self._ctap2_make_credential
            self._do_get_assertion = self._ctap2_get_assertion
        except ValueError:
            self.ctap1 = CTAP1(device)
            self.info = _CTAP1_INFO
            self._do_make_credential = self._ctap1_make_credential
            self._do_get_assertion = self._ctap1_get_assertion

    def _get_ctap_uv(self, uv_requirement, pin_provided):
        pin_supported = "clientPin" in self.info.options
        pin_set = self.info.options.get("clientPin", False)

        if pin_provided:
            if not pin_set:
                raise ClientError.ERR.BAD_REQUEST("PIN provided, but not set/supported")
            else:
                return False  # If PIN is provided, internal uv is not used

        uv_supported = "uv" in self.info.options
        uv_set = self.info.options.get("uv", False)

        if uv_requirement == UserVerificationRequirement.REQUIRED:
            if not uv_set:
                raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(
                    "User verification not configured/supported"
                )
            return True
        elif uv_requirement == UserVerificationRequirement.PREFERRED:
            if not uv_set and (uv_supported or pin_supported):
                raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(
                    "User verification supported but not configured"
                )
            return uv_set

        return False

    def make_credential(self, options, **kwargs):
        """Creates a credential.

        :param options: PublicKeyCredentialCreationOptions data.
        :param pin: (optional) Used if PIN verification is required.
        :param threading.Event event: (optional) Signal to abort the operation.
        :param on_keepalive: (optional) function to call with CTAP status updates.
        """

        options = PublicKeyCredentialCreationOptions._wrap(options)
        pin = kwargs.get("pin")
        event = kwargs.get("event", Event())
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        self._verify_rp_id(options.rp.id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.MAKE_CREDENTIAL, options.challenge
        )

        selection = options.authenticator_selection or AuthenticatorSelectionCriteria()

        try:
            return (
                self._do_make_credential(
                    client_data,
                    options.rp,
                    options.user,
                    options.pub_key_cred_params,
                    options.exclude_credentials,
                    options.extensions,
                    selection.require_resident_key,
                    self._get_ctap_uv(selection.user_verification, pin is not None),
                    pin,
                    event,
                    kwargs.get("on_keepalive"),
                ),
                client_data,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def _ctap2_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list,
        extensions,
        rk,
        uv,
        pin,
        event,
        on_keepalive,
    ):
        pin_auth = None
        pin_protocol = None
        if pin:
            pin_protocol = self.pin_protocol.VERSION
            pin_token = self.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, client_data.hash)[:16]
        elif self.info.options.get("clientPin") and not uv:
            raise ClientError.ERR.BAD_REQUEST("PIN required but not provided")

        if not (rk or uv):
            options = None
        else:
            options = {}
            if rk:
                options["rk"] = True
            if uv:
                options["uv"] = True

        if exclude_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                exclude_list = [e for e in exclude_list if len(e) <= max_len]

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(exclude_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("exclude_list too long")

        return self.ctap2.make_credential(
            client_data.hash,
            rp,
            user,
            key_params,
            exclude_list,
            extensions,
            options,
            pin_auth,
            pin_protocol,
            event,
            on_keepalive,
        )

    def _ctap1_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list,
        extensions,
        rk,
        uv,
        pin,
        event,
        on_keepalive,
    ):
        if rk or uv or ES256.ALGORITHM not in [p.alg for p in key_params]:
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp["id"].encode())

        dummy_param = b"\0" * 32
        for cred in exclude_list or []:
            key_handle = cred["id"]
            try:
                self.ctap1.authenticate(dummy_param, app_param, key_handle, True)
                raise ClientError.ERR.OTHER_ERROR()  # Shouldn't happen
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    _call_polling(
                        self.ctap1_poll_delay,
                        event,
                        on_keepalive,
                        self.ctap1.register,
                        dummy_param,
                        dummy_param,
                    )
                    raise ClientError.ERR.DEVICE_INELIGIBLE()

        return AttestationObject.from_ctap1(
            app_param,
            _call_polling(
                self.ctap1_poll_delay,
                event,
                on_keepalive,
                self.ctap1.register,
                client_data.hash,
                app_param,
            ),
        )

    def get_assertion(self, options, **kwargs):
        """Get an assertion.

        :param options: PublicKeyCredentialRequestOptions data.
        :param pin: (optional) Used if PIN verification is required.
        :param threading.Event event: (optional) Signal to abort the operation.
        :param on_keepalive: (optional) Not implemented.
        """

        options = PublicKeyCredentialRequestOptions._wrap(options)
        pin = kwargs.get("pin")
        event = kwargs.get("event", Event())
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        self._verify_rp_id(options.rp_id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.GET_ASSERTION, options.challenge
        )

        try:
            return (
                self._do_get_assertion(
                    client_data,
                    options.rp_id,
                    options.allow_credentials,
                    options.extensions,
                    self._get_ctap_uv(options.user_verification, pin is not None),
                    pin,
                    event,
                    kwargs.get("on_keepalive"),
                ),
                client_data,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def _ctap2_get_assertion(
        self, client_data, rp_id, allow_list, extensions, uv, pin, event, on_keepalive
    ):
        pin_auth = None
        pin_protocol = None
        if pin:
            pin_protocol = self.pin_protocol.VERSION
            pin_token = self.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, client_data.hash)[:16]
        elif self.info.options.get("clientPin") and not uv:
            raise ClientError.ERR.BAD_REQUEST("PIN required but not provided")

        if uv:
            options = {"uv": True}
        else:
            options = None

        if allow_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                allow_list = [e for e in allow_list if len(e) <= max_len]
            if not allow_list:
                raise CtapError(CtapError.ERR.NO_CREDENTIALS)

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(allow_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("allow_list too long")

        return self.ctap2.get_assertions(
            rp_id,
            client_data.hash,
            allow_list,
            extensions,
            options,
            pin_auth,
            pin_protocol,
            event,
            on_keepalive,
        )

    def _ctap1_get_assertion(
        self, client_data, rp_id, allow_list, extensions, uv, pin, event, on_keepalive
    ):
        if uv or not allow_list:
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp_id.encode())
        client_param = client_data.hash
        for cred in allow_list:
            try:
                auth_resp = _call_polling(
                    self.ctap1_poll_delay,
                    event,
                    on_keepalive,
                    self.ctap1.authenticate,
                    client_param,
                    app_param,
                    cred["id"],
                )
                return [AssertionResponse.from_ctap1(app_param, cred, auth_resp)]
            except ClientError as e:
                if e.code == ClientError.ERR.TIMEOUT:
                    raise  # Other errors are ignored so we move to the next.
        raise ClientError.ERR.DEVICE_INELIGIBLE()


_WIN_INFO = Info.create(["U2F_V2", "FIDO_2_0"])

if platform.system().lower() == "windows":
    try:
        from .win_api import (
            WinAPI,
            WebAuthNAuthenticatorAttachment,
            WebAuthNUserVerificationRequirement,
            WebAuthNAttestationConvoyancePreference,
        )
    except Exception:  # TODO: Make this less generic
        pass


class WindowsClient(_BaseClient):
    """Fido2Client-like class using the Windows WebAuthn API.

    Note: This class only works on Windows 10 19H1 or later. This is also when Windows
    started restricting access to FIDO devices, causing the standard client classes to
    require admin priveleges to run (unlike this one).

    The make_credential and get_assertion methods are intended to work as a drop-in
    replacement for the Fido2Client methods of the same name.

    :param str origin: The origin to use.
    :param verify: Function to verify an RP ID for a given origin.
    :param ctypes.wintypes.HWND handle: (optional) Window reference to use.
    """

    def __init__(self, origin, verify=verify_rp_id, handle=None):
        super(WindowsClient, self).__init__(origin, verify)
        self.api = WinAPI(handle)

    @property
    def info(self):
        return _WIN_INFO

    @staticmethod
    def is_available():
        return platform.system().lower() == "windows" and WinAPI.version > 0

    def make_credential(self, options, **kwargs):
        """Create a credential using Windows WebAuthN APIs.

        :param options: PublicKeyCredentialCreationOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialCreationOptions._wrap(options)

        self._verify_rp_id(options.rp.id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.MAKE_CREDENTIAL, options.challenge
        )

        selection = options.authenticator_selection or AuthenticatorSelectionCriteria()

        try:
            result = self.api.make_credential(
                options.rp,
                options.user,
                options.pub_key_cred_params,
                client_data,
                options.timeout or 0,
                selection.require_resident_key or False,
                WebAuthNAuthenticatorAttachment.from_string(
                    selection.authenticator_attachment or "any"
                ),
                WebAuthNUserVerificationRequirement.from_string(
                    selection.user_verification or "discouraged"
                ),
                WebAuthNAttestationConvoyancePreference.from_string(
                    options.attestation or "none"
                ),
                options.exclude_credentials,
                options.extensions,
                kwargs.get("event"),
            )
        except OSError as e:
            raise ClientError.ERR.OTHER_ERROR(e)

        return AttestationObject(result), client_data

    def get_assertion(self, options, **kwargs):
        """Get assertion using Windows WebAuthN APIs.

        :param options: PublicKeyCredentialRequestOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialRequestOptions._wrap(options)

        self._verify_rp_id(options.rp_id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.GET_ASSERTION, options.challenge
        )

        try:
            (credential, auth_data, signature, user_id) = self.api.get_assertion(
                options.rp_id,
                client_data,
                options.timeout or 0,
                WebAuthNAuthenticatorAttachment.ANY,
                WebAuthNUserVerificationRequirement.from_string(
                    options.user_verification or "discouraged"
                ),
                options.allow_credentials,
                options.extensions,
                kwargs.get("event"),
            )
        except OSError as e:
            raise ClientError.ERR.OTHER_ERROR(e)

        user = {"id": user_id} if user_id else None
        return (
            [AssertionResponse.create(credential, auth_data, signature, user)],
            client_data,
        )
