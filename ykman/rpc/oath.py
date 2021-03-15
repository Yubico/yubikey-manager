# Copyright (c) 2021 Yubico AB
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


from .base import RpcNode, action, child
from yubikit.core import require_version, NotSupportedError
from yubikit.oath import OathSession, CredentialData, OATH_TYPE, HASH_ALGORITHM
from dataclasses import asdict


class OathNode(RpcNode):
    def __init__(self, connection):
        super().__init__()
        self.session = OathSession(connection)

    def get_data(self):
        return dict(
            version=self.session.version,
            device_id=self.session.device_id,
            locked=self.session.locked,
        )

    def list_children(self):
        children = super().list_children()
        if self.session.locked:
            del children["accounts"]
        return children

    @action
    def derive(self, params, event, signal):
        return dict(key=self.session.derive_key(params.pop("password")))

    @action
    def validate(self, params, event, signal):
        if "password" in params:
            key = self.session.derive_key(params.pop("password"))
        else:
            key = bytes.fromhex(params.pop("key"))
        self.session.validate(key)
        return dict()

    @child
    def accounts(self):
        return CredentialsNode(self.session)


class CredentialsNode(RpcNode):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.refresh()

    def refresh(self):
        self._creds = {c.id: c for c in self.session.list_credentials()}
        if self._child and self._child_name not in self._creds:
            self._close_child()

    def list_children(self):
        return {c_id.decode(): asdict(c) for c_id, c in self._creds.items()}

    def create_child(self, name):
        key = name.encode()
        if key in self._creds:
            return CredentialNode(self.session, self._creds[key], self.refresh)
        return super().create_child(name)

    @action
    def put(self, params, event, signal):
        require_touch = params.pop("require_touch", False)
        if "uri" in params:
            data = CredentialData.parse_uri(params.pop("uri"))
            if params:
                raise ValueError("Unsupported parameters present")
        else:
            data = CredentialData(
                params.pop("name"),
                OATH_TYPE[params.pop("oath_type").upper()],
                HASH_ALGORITHM[params.pop("hash", "sha1".upper())],
                bytes.fromhex(params.pop("secret")),
                **params
            )

        if data.get_id() in self._creds:
            raise ValueError("Credential already exists")
        credential = self.session.put_credential(data, require_touch)
        self._creds[credential.id] = credential
        return asdict(credential)


class CredentialNode(RpcNode):
    def __init__(self, session, credential, refresh):
        super().__init__()
        self.session = session
        self.credential = credential
        self.refresh = refresh

    def list_actions(self):
        actions = super().list_actions()
        try:
            require_version(self.session.version, (5, 3, 1))
        except NotSupportedError:
            actions.remove("rename")
        return actions

    def get_info(self):
        return asdict(self.credential)

    @action
    def code(self, params, event, signal):
        timestamp = params.pop("timestamp", None)
        code = self.session.calculate_code(self.credential, timestamp)
        return asdict(code)

    @action
    def calculate(self, params, event, signal):
        challenge = bytes.fromhex(params.pop("challenge"))
        response = self.session.calculate(self.credential.id, challenge)
        return dict(response=response.hex())

    @action
    def delete(self, params, event, signal):
        self.session.delete_credential(self.credential.id)
        self.refresh()
        self.credential = None
        return dict()

    @action
    def rename(self, params, event, signal):
        name = params.pop("name")
        issuer = params.pop("issuer", None)
        new_id = self.session.rename_credential(self.credential.id, name, issuer)
        self.refresh()
        return dict(credential_id=new_id.decode())
