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

from .utils import sha256
from enum import Enum, unique
import six
import re

"""
Data classes based on the W3C WebAuthn specification (https://www.w3.org/TR/webauthn/).

See the specification for a description and details on their usage.
"""


class _StringEnum(six.text_type, Enum):
    @classmethod
    def _wrap(cls, value):
        if value is None:
            return None
        return cls(value)


@unique
class AttestationConveyancePreference(_StringEnum):
    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"


@unique
class UserVerificationRequirement(_StringEnum):
    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


@unique
class AuthenticatorAttachment(_StringEnum):
    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


@unique
class AuthenticatorTransport(_StringEnum):
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"


@unique
class PublicKeyCredentialType(_StringEnum):
    PUBLIC_KEY = "public-key"


def _snake2camel(name):
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _camel2snake(name):
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


class _DataObject(dict):
    """Base class for WebAuthn data types, acting both as dict and providing attribute
    access to values.
    """

    def __init__(self, **data):
        keys = {k: _snake2camel(k) for k in data.keys()}
        super(_DataObject, self).__init__(
            {keys[k]: v for k, v in data.items() if v is not None}
        )
        super(_DataObject, self).__setattr__("_keys", keys)

    def __getattr__(self, name):
        if name in self._keys:
            return self.get(self._keys[name])
        raise AttributeError(
            "'{}' object has no attribute '{}'".format(type(self).__name__, name)
        )

    def __setattr__(self, name, value):
        if name in self._keys:
            self[self._keys[name]] = value
        else:
            raise AttributeError(
                "'{}' object has no attribute '{}'".format(type(self).__name__, name)
            )

    def __repr__(self):
        return "{}({!r})".format(self.__class__.__name__, dict(self))

    @classmethod
    def _wrap(cls, data):
        if data is None:
            return None
        if isinstance(data, cls):
            return data
        return cls(**{_camel2snake(k): v for k, v in data.items()})

    @classmethod
    def _wrap_list(cls, datas):
        return [cls._wrap(x) for x in datas] if datas is not None else None


class PublicKeyCredentialRpEntity(_DataObject):
    def __init__(self, id, name, icon=None):
        super(PublicKeyCredentialRpEntity, self).__init__(id=id, name=name, icon=icon)

    @property
    def id_hash(self):
        """Return SHA256 hash of the identifier."""
        return sha256(self.id.encode("utf8"))


class PublicKeyCredentialUserEntity(_DataObject):
    def __init__(self, id, name, icon=None, display_name=None):
        super(PublicKeyCredentialUserEntity, self).__init__(
            id=id, name=name, icon=icon, display_name=display_name
        )


class PublicKeyCredentialParameters(_DataObject):
    def __init__(self, type, alg):
        super(PublicKeyCredentialParameters, self).__init__(
            type=PublicKeyCredentialType(type), alg=alg
        )


class PublicKeyCredentialDescriptor(_DataObject):
    def __init__(self, type, id, transports=None):
        super(PublicKeyCredentialDescriptor, self).__init__(
            type=PublicKeyCredentialType(type),
            id=id,
            transports=transports,  # Note: Type is str as in current WebAuthn draft!
        )


class AuthenticatorSelectionCriteria(_DataObject):
    def __init__(
        self,
        authenticator_attachment=None,
        require_resident_key=None,
        user_verification=None,
    ):
        super(AuthenticatorSelectionCriteria, self).__init__(
            authenticator_attachment=AuthenticatorAttachment._wrap(
                authenticator_attachment
            ),
            require_resident_key=require_resident_key,
            user_verification=UserVerificationRequirement._wrap(user_verification),
        )


class PublicKeyCredentialCreationOptions(_DataObject):
    def __init__(
        self,
        rp,
        user,
        challenge,
        pub_key_cred_params,
        timeout=None,
        exclude_credentials=None,
        authenticator_selection=None,
        attestation=None,
        extensions=None,
    ):
        super(PublicKeyCredentialCreationOptions, self).__init__(
            rp=PublicKeyCredentialRpEntity._wrap(rp),
            user=PublicKeyCredentialUserEntity._wrap(user),
            challenge=challenge,
            pub_key_cred_params=PublicKeyCredentialParameters._wrap_list(
                pub_key_cred_params
            ),
            timeout=timeout,
            exclude_credentials=PublicKeyCredentialDescriptor._wrap_list(
                exclude_credentials
            ),
            authenticator_selection=AuthenticatorSelectionCriteria._wrap(
                authenticator_selection
            ),
            attestation=AttestationConveyancePreference._wrap(attestation),
            extensions=extensions,
        )


class PublicKeyCredentialRequestOptions(_DataObject):
    def __init__(
        self,
        challenge,
        timeout=None,
        rp_id=None,
        allow_credentials=None,
        user_verification=None,
        extensions=None,
    ):
        super(PublicKeyCredentialRequestOptions, self).__init__(
            challenge=challenge,
            timeout=timeout,
            rp_id=rp_id,
            allow_credentials=PublicKeyCredentialDescriptor._wrap_list(
                allow_credentials
            ),
            user_verification=UserVerificationRequirement._wrap(user_verification),
            extensions=extensions,
        )
