# Copyright (c) 2017 Yubico AB
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

import os
import json
import keyring
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


XDG_DATA_HOME = os.environ.get("XDG_DATA_HOME", "~/.local/share") + "/ykman"
XDG_CONFIG_HOME = os.environ.get("XDG_CONFIG_HOME", "~/.config") + "/ykman"

KEYRING_SERVICE = os.environ.get("YKMAN_KEYRING_SERVICE", "ykman")
KEYRING_KEY = os.environ.get("YKMAN_KEYRING_KEY", "wrap_key")


class Settings(dict):
    _config_dir = XDG_CONFIG_HOME

    def __init__(self, name):
        self.fname = Path(self._config_dir).expanduser().resolve() / (name + ".json")
        if self.fname.is_file():
            with self.fname.open("r") as fd:
                self.update(json.load(fd))

    def __eq__(self, other):
        return other is not None and self.fname == other.fname

    def __ne__(self, other):
        return other is None or self.fname != other.fname

    def write(self):
        conf_dir = self.fname.parent
        if not conf_dir.is_dir():
            conf_dir.mkdir(0o700, parents=True)
        with self.fname.open("w") as fd:
            json.dump(self, fd, indent=2)

    __hash__ = None


class Configuration(Settings):
    _config_dir = XDG_CONFIG_HOME


class KeystoreError(Exception):
    """Error accessing the OS keystore"""


class UnwrapValueError(Exception):
    """Error unwrapping a particular secret value"""


class AppData(Settings):
    _config_dir = XDG_DATA_HOME

    def __init__(self, name, keyring_service=KEYRING_SERVICE, keyring_key=KEYRING_KEY):
        super().__init__(name)
        self._service = keyring_service
        self._username = keyring_key

    @property
    def keyring_unlocked(self) -> bool:
        return hasattr(self, "_fernet")

    def ensure_unlocked(self):
        if not self.keyring_unlocked:
            try:
                wrap_key = keyring.get_password(self._service, self._username)
            except keyring.errors.KeyringError:
                raise KeystoreError("Keyring locked or unavailable")

            if wrap_key is None:
                key = Fernet.generate_key()
                keyring.set_password(self._service, self._username, key.decode())
                self._fernet = Fernet(key)
            else:
                self._fernet = Fernet(wrap_key)

    def get_secret(self, key: str):
        self.ensure_unlocked()
        try:
            return json.loads(self._fernet.decrypt(self[key].encode()))
        except InvalidToken:
            raise UnwrapValueError("Undecryptable value")

    def put_secret(self, key: str, value) -> None:
        self.ensure_unlocked()
        self[key] = self._fernet.encrypt(json.dumps(value).encode()).decode()
