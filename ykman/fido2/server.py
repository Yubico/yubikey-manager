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

from .rpid import verify_rp_id, verify_app_id
from .cose import CoseKey
from .ctap2 import AttestedCredentialData
from .client import WEBAUTHN_TYPE
from .attestation import Attestation, FidoU2FAttestation, UnsupportedAttestation
from .utils import websafe_encode, websafe_decode
from .webauthn import (
    AttestationConveyancePreference,
    PublicKeyCredentialRpEntity,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    PublicKeyCredentialParameters,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
)


import os
from cryptography.hazmat.primitives import constant_time
from cryptography.exceptions import InvalidSignature


def _verify_origin_for_rp(rp_id):
    return lambda o: verify_rp_id(rp_id, o)


def _default_attestations():
    return [
        cls()
        for cls in Attestation.__subclasses__()
        if getattr(cls, "FORMAT", "none") != "none"
    ]


def _validata_challenge(challenge):
    if challenge is None:
        challenge = os.urandom(32)
    else:
        if not isinstance(challenge, bytes):
            raise TypeError("Custom challenge must be of type 'bytes'.")
        if len(challenge) < 16:
            raise ValueError("Custom challenge length must be >= 16.")
    return challenge


def to_descriptor(credential, transports=None):
    """Converts an AttestedCredentialData to a PublicKeyCredentialDescriptor.

    :param credential: AttestedCredentialData containing the credential ID to use.
    :param transports: Optional list of AuthenticatorTransport strings to add to the
        descriptor.
    :return: A descriptor of the credential, for use with register_begin or
        authenticate_begin.
    :rtype: PublicKeyCredentialDescriptor
    """
    return PublicKeyCredentialDescriptor(
        PublicKeyCredentialType.PUBLIC_KEY, credential.credential_id, transports
    )


def _wrap_credentials(creds):
    if creds is None:
        return None
    return [
        to_descriptor(c)
        if isinstance(c, AttestedCredentialData)
        else PublicKeyCredentialDescriptor._wrap(c)
        for c in creds
    ]


class Fido2Server(object):
    """FIDO2 server

    :param rp: Relying party data as `PublicKeyCredentialRpEntity` instance.
    :param attestation: (optional) Requirement on authenticator attestation.
    :param verify_origin: (optional) Alternative function to validate an origin.
    :param attestation_types: (optional) List of `Attestation` subclasses to use
        to verify attestation. By default, all available subclasses of
        `Attestation` will be used, excluding the NoneAttestation format. This
        parameter is ignored if `attestation` is set to `none`.
    """

    def __init__(
        self, rp, attestation=None, verify_origin=None, attestation_types=None
    ):
        self.rp = PublicKeyCredentialRpEntity._wrap(rp)
        self._verify = verify_origin or _verify_origin_for_rp(self.rp.id)
        self.timeout = 30000
        self.attestation = AttestationConveyancePreference._wrap(attestation)
        self.allowed_algorithms = [
            PublicKeyCredentialParameters("public-key", alg)
            for alg in CoseKey.supported_algorithms()
        ]
        self._attestation_types = attestation_types or _default_attestations()

    def register_begin(
        self,
        user,
        credentials=None,
        resident_key=None,
        user_verification=None,
        authenticator_attachment=None,
        challenge=None,
    ):
        """Return a PublicKeyCredentialCreationOptions registration object and
        the internal state dictionary that needs to be passed as is to the
        corresponding `register_complete` call.

        :param user: The dict containing the user data.
        :param credentials: The list of previously registered credentials, these can be
            of type AttestedCredentialData, or PublicKeyCredentialDescriptor.
        :param resident_key: True to request a resident credential.
        :param user_verification: The desired USER_VERIFICATION level.
        :param authenticator_attachment: The desired AUTHENTICATOR_ATTACHMENT
            or None to not provide a preference (and get both types).
        :param challenge: A custom challenge to sign and verify or None to use
            OS-specific random bytes.
        :return: Registration data, internal state."""
        if not self.allowed_algorithms:
            raise ValueError("Server has no allowed algorithms.")

        challenge = _validata_challenge(challenge)

        state = self._make_internal_state(challenge, user_verification)

        return (
            {
                "publicKey": PublicKeyCredentialCreationOptions(
                    self.rp,
                    user,
                    challenge,
                    self.allowed_algorithms,
                    self.timeout,
                    _wrap_credentials(credentials),
                    AuthenticatorSelectionCriteria(
                        authenticator_attachment, resident_key, user_verification
                    )
                    if any((authenticator_attachment, resident_key, user_verification))
                    else None,
                    self.attestation,
                )
            },
            state,
        )

    def register_complete(self, state, client_data, attestation_object):
        """Verify the correctness of the registration data received from
        the client.

        :param state: The state data returned by the corresponding
            `register_begin`.
        :param client_data: The client data.
        :param attestation_object: The attestation object.
        :return: The authenticator data"""
        if client_data.get("type") != WEBAUTHN_TYPE.MAKE_CREDENTIAL:
            raise ValueError("Incorrect type in ClientData.")
        if not self._verify(client_data.get("origin")):
            raise ValueError("Invalid origin in ClientData.")
        if not constant_time.bytes_eq(
            websafe_decode(state["challenge"]), client_data.challenge
        ):
            raise ValueError("Wrong challenge in response.")
        if not constant_time.bytes_eq(
            self.rp.id_hash, attestation_object.auth_data.rp_id_hash
        ):
            raise ValueError("Wrong RP ID hash in response.")
        if not attestation_object.auth_data.is_user_present():
            raise ValueError("User Present flag not set.")

        if (
            state["user_verification"] == UserVerificationRequirement.REQUIRED
            and not attestation_object.auth_data.is_user_verified()
        ):
            raise ValueError(
                "User verification required, but User Verified flag not set."
            )

        if self.attestation not in (None, AttestationConveyancePreference.NONE):
            att_verifier = UnsupportedAttestation(attestation_object.fmt)
            for at in self._attestation_types:
                if getattr(at, "FORMAT", None) == attestation_object.fmt:
                    att_verifier = at
                    break
            # An unsupported format causes an exception to be thrown, which
            # includes the auth_data. The caller may choose to handle this case
            # and allow the registration.
            att_verifier.verify(
                attestation_object.att_statement,
                attestation_object.auth_data,
                client_data.hash,
            )
        # We simply ignore attestation if self.attestation == 'none', as not all
        # clients strip the attestation.

        return attestation_object.auth_data

    def authenticate_begin(
        self, credentials=None, user_verification=None, challenge=None
    ):
        """Return a PublicKeyCredentialRequestOptions assertion object and the internal
        state dictionary that needs to be passed as is to the corresponding
        `authenticate_complete` call.

        :param credentials: The list of previously registered credentials, these can be
            of type AttestedCredentialData, or PublicKeyCredentialDescriptor.
        :param user_verification: The desired USER_VERIFICATION level.
        :param challenge: A custom challenge to sign and verify or None to use
            OS-specific random bytes.
        :return: Assertion data, internal state."""
        challenge = _validata_challenge(challenge)

        state = self._make_internal_state(challenge, user_verification)

        return (
            {
                "publicKey": PublicKeyCredentialRequestOptions(
                    challenge,
                    self.timeout,
                    self.rp.id,
                    _wrap_credentials(credentials),
                    user_verification,
                )
            },
            state,
        )

    def authenticate_complete(
        self, state, credentials, credential_id, client_data, auth_data, signature
    ):
        """Verify the correctness of the assertion data received from
        the client.

        :param state: The state data returned by the corresponding
            `register_begin`.
        :param credentials: The list of previously registered credentials.
        :param credential_id: The credential id from the client response.
        :param client_data: The client data.
        :param auth_data: The authenticator data.
        :param signature: The signature provided by the client."""
        if client_data.get("type") != WEBAUTHN_TYPE.GET_ASSERTION:
            raise ValueError("Incorrect type in ClientData.")
        if not self._verify(client_data.get("origin")):
            raise ValueError("Invalid origin in ClientData.")
        if websafe_decode(state["challenge"]) != client_data.challenge:
            raise ValueError("Wrong challenge in response.")
        if not constant_time.bytes_eq(self.rp.id_hash, auth_data.rp_id_hash):
            raise ValueError("Wrong RP ID hash in response.")
        if not auth_data.is_user_present():
            raise ValueError("User Present flag not set.")

        if (
            state["user_verification"] == UserVerificationRequirement.REQUIRED
            and not auth_data.is_user_verified()
        ):
            raise ValueError(
                "User verification required, but user verified flag not set."
            )

        for cred in credentials:
            if cred.credential_id == credential_id:
                try:
                    cred.public_key.verify(auth_data + client_data.hash, signature)
                except InvalidSignature:
                    raise ValueError("Invalid signature.")
                return cred
        raise ValueError("Unknown credential ID.")

    @staticmethod
    def _make_internal_state(challenge, user_verification):
        return {
            "challenge": websafe_encode(challenge),
            "user_verification": user_verification,
        }


class U2FFido2Server(Fido2Server):
    """Fido2Server which can be used with existing U2F credentials.

    This Fido2Server can be used with existing U2F credentials by using the
    WebAuthn appid extension, as well as with new WebAuthn credentials.
    See https://www.w3.org/TR/webauthn/#sctn-appid-extension for details.

    :param app_id: The appId which was used for U2F registration.
    :param verify_u2f_origin: (optional) Alternative function to validate an
        origin for U2F credentials..
    For other parameters, see Fido2Server.
    """

    def __init__(self, app_id, rp, verify_u2f_origin=None, *args, **kwargs):
        super(U2FFido2Server, self).__init__(rp, *args, **kwargs)
        kwargs["attestation_types"] = [FidoU2FAttestation()]
        if verify_u2f_origin:
            kwargs["verify_origin"] = verify_u2f_origin
        else:
            kwargs["verify_origin"] = lambda o: verify_app_id(app_id, o)
        self._app_id = app_id
        self._app_id_server = Fido2Server(
            PublicKeyCredentialRpEntity(app_id, self.rp.name), *args, **kwargs
        )

    def register_begin(self, *args, **kwargs):
        req, state = super(U2FFido2Server, self).register_begin(*args, **kwargs)
        req["publicKey"].setdefault("extensions", {})["appidExclude"] = self._app_id
        return req, state

    def authenticate_begin(self, *args, **kwargs):
        req, state = super(U2FFido2Server, self).authenticate_begin(*args, **kwargs)
        req["publicKey"].setdefault("extensions", {})["appid"] = self._app_id
        return req, state

    def authenticate_complete(self, *args, **kwargs):
        try:
            return super(U2FFido2Server, self).authenticate_complete(*args, **kwargs)
        except ValueError:
            return self._app_id_server.authenticate_complete(*args, **kwargs)
