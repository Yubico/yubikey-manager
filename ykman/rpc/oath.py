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


from .base import ParentNode, CommandNode, command, child
from yubikit.oath import OathSession, CredentialData, OATH_TYPE, HASH_ALGORITHM
from dataclasses import asdict


class OathNode(ParentNode):
    def __init__(self, connection):
        super().__init__()
        self.session = OathSession(connection)

    def invoke(self, request, event, signal):
        return dict(
            version=self.session.version,
            device_id=self.session.device_id,
            locked=self.session.locked,
        )

    @command
    def derive(self, request, event, signal):
        return dict(key=self.session.derive_key(request.pop("password")))

    @command
    def validate(self, request, event, signal):
        if "password" in request:
            key = self.session.derive_key(request.pop("password"))
        else:
            key = bytes.fromhex(request.pop("key"))
        self.session.validate(key)
        return dict()

    @command
    def calculate(self, request, event, signal):
        credential_id = bytes.fromhex(request.pop("credential"))
        challenge = bytes.fromhex(request.pop("challenge"))
        response = self.session.calculate(credential_id, challenge)
        return dict(response=response.hex())

    @child
    def accounts(self):
        return CredentialsNode(self.session)


class CredentialsNode(ParentNode):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self._creds = {c.id: c for c in self.session.list_credentials()}

    def invoke(self, request, event, signal):
        return dict(credentials=[asdict(c) for c in sorted(self._creds.values())])

    def create_child(self, name):
        key = name.encode()
        if key in self._creds:
            return CredentialNode(self.session, self._creds[key])
        return super().create_child(name)

    @command
    def delete(self, request, event, signal):
        credential_id = request.pop("credential").encode()
        self.session.delete_credential(credential_id)
        del self._creds[credential_id]
        return dict()

    def _put_credential(self, data, require_touch):
        if data.get_id() in self._creds:
            raise ValueError("Credential already exists")
        credential = self.session.put_credential(data, require_touch)
        self._creds[credential.id] = credential
        return asdict(credential)

    @command
    def put_data(self, request, event, signal):
        require_touch = request.pop("require_touch", False)
        data = CredentialData(
            request.pop("name"),
            OATH_TYPE[request.pop("oath_type").upper()],
            HASH_ALGORITHM[request.pop("hash", "sha1".upper())],
            bytes.fromhex(request.pop("secret")),
            **request
        )
        return self._put_credential(data, require_touch)

    @command
    def put_uri(self, request, event, signal):
        require_touch = request.pop("require_touch", False)
        data = CredentialData.parse_uri(request.pop("uri"))
        return self._put_credential(data, require_touch)


class CredentialNode(CommandNode):
    def __init__(self, session, credential):
        super().__init__()
        self.session = session
        self.credential = credential

    def invoke(self, request, event, signal):
        return asdict(self.credential)

    @command
    def code(self, request, event, signal):
        timestamp = request.pop("timestamp", None)
        code = self.session.calculate_code(self.credential, timestamp)
        return asdict(code)

    @command
    def calculate(self, request, event, signal):
        challenge = bytes.fromhex(request.pop("challenge"))
        response = self.session.calculate(self.credential.id, challenge)
        return dict(response=response.hex())

    @command
    def delete(self, request, event, signal):
        self.session.delete_credential(self.credential.id)
        return dict()
