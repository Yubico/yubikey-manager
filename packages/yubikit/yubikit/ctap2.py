# Copyright (c) 2020 Yubico AB
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

"""CTAP2 session and command facades.

These classes abstract over the transport-specific native backends
(SmartCard / FIDO HID), provide context-manager support, and
automatically restore ownership of the underlying session when a
command object (ClientPin, CredentialManagement) is closed or
exits its ``with`` block.
"""

from __future__ import annotations

import logging
from typing import Any

from _yubikit_native.sessions import BioEnrollmentCcid as _BioEnrollmentCcid
from _yubikit_native.sessions import BioEnrollmentFido as _BioEnrollmentFido
from _yubikit_native.sessions import ClientPinCcid as _ClientPinCcid
from _yubikit_native.sessions import ClientPinFido as _ClientPinFido
from _yubikit_native.sessions import ConfigCcid as _ConfigCcid
from _yubikit_native.sessions import ConfigFido as _ConfigFido
from _yubikit_native.sessions import (
    CredentialManagementCcid as _CredentialManagementCcid,
)
from _yubikit_native.sessions import (
    CredentialManagementFido as _CredentialManagementFido,
)
from _yubikit_native.sessions import Ctap2SessionCcid as _Ctap2SessionCcid
from _yubikit_native.sessions import Ctap2SessionFido as _Ctap2SessionFido
from _yubikit_native.sessions import LargeBlobsCcid as _LargeBlobsCcid
from _yubikit_native.sessions import LargeBlobsFido as _LargeBlobsFido
from _yubikit_native.sessions import PinProtocol as _PinProtocol

from .core import Closable, Session, Version
from .core.fido import FidoConnection
from .core.smartcard import SmartCardConnection
from .core.smartcard.scp import ScpKeyParams

logger = logging.getLogger(__name__)

PERMISSION_MAKE_CREDENTIAL = 0x01
PERMISSION_GET_ASSERTION = 0x02
PERMISSION_CREDENTIAL_MGMT = 0x04
PERMISSION_BIO_ENROLLMENT = 0x08
PERMISSION_LARGE_BLOB_WRITE = 0x10
PERMISSION_AUTHENTICATOR_CONFIG = 0x20


class PinProtocol:
    """PIN/UV protocol identifier (v1 or v2)."""

    def __init__(self, version: int) -> None:
        self._native = _PinProtocol(version)

    @property
    def version(self) -> int:
        return self._native.version


class Ctap2Session(Session):
    """CTAP2 session facade over SmartCard or FIDO HID transports."""

    def __init__(
        self,
        connection: SmartCardConnection | FidoConnection,
        scp_key_params: ScpKeyParams | None = None,
    ) -> None:
        if isinstance(connection, SmartCardConnection):
            self._native: _Ctap2SessionCcid | _Ctap2SessionFido = _Ctap2SessionCcid(
                connection, scp_key_params
            )
        elif isinstance(connection, FidoConnection):
            if scp_key_params:
                raise ValueError("SCP can only be used with SmartCardConnection")
            self._native = _Ctap2SessionFido(connection)
        else:
            raise TypeError("Unsupported connection type")

        self._version = Version(*self._native.version)
        logger.debug(
            "CTAP2 session initialized for "
            f"connection={type(connection).__name__}, version={self.version}"
        )

    @property
    def version(self) -> Version:
        return self._version

    def get_info(self) -> dict[str, Any]:
        return self._native.get_info()

    def selection(
        self,
        event: object | None = None,
        on_keepalive: object | None = None,
    ) -> None:
        self._native.selection(event, on_keepalive)

    def send_cbor(
        self,
        cmd: int,
        data: bytes | None = None,
        event: object | None = None,
        on_keepalive: object | None = None,
    ) -> bytes:
        return self._native.send_cbor(cmd, data, event, on_keepalive)

    def reset(
        self,
        event: object | None = None,
        on_keepalive: object | None = None,
    ) -> None:
        self._native.reset(event, on_keepalive)


class ClientPin(Closable):
    """ClientPIN command facade with context-manager support.

    Usage::

        session = Ctap2Session(connection)
        with ClientPin(session) as client_pin:
            token = client_pin.get_pin_token(pin, permissions=0x04)
        # session is usable again here
    """

    def __init__(
        self,
        session: Ctap2Session,
        protocol: PinProtocol | None = None,
    ) -> None:
        self._session = session
        proto = protocol._native if protocol else None
        native = session._native
        if isinstance(native, _Ctap2SessionCcid):
            self._native: _ClientPinCcid | _ClientPinFido = _ClientPinCcid(
                native, proto
            )
        else:
            self._native = _ClientPinFido(native, proto)

    def close(self) -> None:
        """Restore the session so it can be reused."""
        native_session = self._session._native
        if isinstance(self._native, _ClientPinCcid) and isinstance(
            native_session, _Ctap2SessionCcid
        ):
            self._native.close(native_session)
        elif isinstance(self._native, _ClientPinFido) and isinstance(
            native_session, _Ctap2SessionFido
        ):
            self._native.close(native_session)

    @property
    def protocol(self) -> PinProtocol:
        proto = PinProtocol.__new__(PinProtocol)
        proto._native = self._native.protocol
        return proto

    def get_pin_retries(self) -> tuple[int, int | None]:
        return self._native.get_pin_retries()

    def get_uv_retries(self) -> int:
        return self._native.get_uv_retries()

    def set_pin(self, pin: str) -> None:
        self._native.set_pin(pin)

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        self._native.change_pin(old_pin, new_pin)

    def get_pin_token(
        self,
        pin: str,
        permissions: int | None = None,
        permissions_rpid: str | None = None,
    ) -> bytes:
        return self._native.get_pin_token(pin, permissions, permissions_rpid)

    def get_uv_token(
        self,
        permissions: int | None = None,
        permissions_rpid: str | None = None,
        event: object | None = None,
        on_keepalive: object | None = None,
    ) -> bytes:
        return self._native.get_uv_token(
            permissions, permissions_rpid, event, on_keepalive
        )


class CredentialManagement(Closable):
    """Credential Management command facade with context-manager support.

    Usage::

        session = Ctap2Session(connection)
        with ClientPin(session) as client_pin:
            token = client_pin.get_pin_token(pin, permissions=0x04)
            protocol = client_pin.protocol
        with CredentialManagement(session, protocol, token) as cred_mgmt:
            metadata = cred_mgmt.get_metadata()
    """

    def __init__(
        self,
        session: Ctap2Session,
        protocol: PinProtocol,
        pin_token: bytes,
    ) -> None:
        self._session = session
        native = session._native
        if isinstance(native, _Ctap2SessionCcid):
            self._native: _CredentialManagementCcid | _CredentialManagementFido = (
                _CredentialManagementCcid(native, protocol._native, pin_token)
            )
        else:
            self._native = _CredentialManagementFido(
                native, protocol._native, pin_token
            )

    def close(self) -> None:
        """Restore the session so it can be reused."""
        native_session = self._session._native
        if isinstance(self._native, _CredentialManagementCcid) and isinstance(
            native_session, _Ctap2SessionCcid
        ):
            self._native.close(native_session)
        elif isinstance(self._native, _CredentialManagementFido) and isinstance(
            native_session, _Ctap2SessionFido
        ):
            self._native.close(native_session)

    @property
    def is_update_supported(self) -> bool:
        return self._native.is_update_supported

    def get_metadata(self) -> tuple[int, int]:
        return self._native.get_metadata()

    def enumerate_rps(self) -> list[dict[int, Any]]:
        return self._native.enumerate_rps()

    def enumerate_creds(self, rp_id_hash: bytes) -> list[dict[int, Any]]:
        return self._native.enumerate_creds(rp_id_hash)

    def delete_cred(self, credential_id: Any) -> None:
        self._native.delete_cred(credential_id)

    def update_user_info(self, credential_id: Any, user: Any) -> None:
        self._native.update_user_info(credential_id, user)


class Config(Closable):
    """Authenticator Config command facade with context-manager support.

    Usage::

        session = Ctap2Session(connection)
        with ClientPin(session) as client_pin:
            token = client_pin.get_pin_token(pin, permissions=0x20)
            protocol = client_pin.protocol
        with Config(session, protocol, token) as config:
            config.toggle_always_uv()
    """

    def __init__(
        self,
        session: Ctap2Session,
        protocol: PinProtocol,
        pin_token: bytes,
    ) -> None:
        self._session = session
        native = session._native
        if isinstance(native, _Ctap2SessionCcid):
            self._native: _ConfigCcid | _ConfigFido = _ConfigCcid(
                native, protocol._native, pin_token
            )
        else:
            self._native = _ConfigFido(native, protocol._native, pin_token)

    def close(self) -> None:
        """Restore the session so it can be reused."""
        native_session = self._session._native
        if isinstance(self._native, _ConfigCcid) and isinstance(
            native_session, _Ctap2SessionCcid
        ):
            self._native.close(native_session)
        elif isinstance(self._native, _ConfigFido) and isinstance(
            native_session, _Ctap2SessionFido
        ):
            self._native.close(native_session)

    def enable_enterprise_attestation(self) -> None:
        self._native.enable_enterprise_attestation()

    def toggle_always_uv(self) -> None:
        self._native.toggle_always_uv()

    def set_min_pin_length(
        self,
        min_pin_length: int | None = None,
        rp_ids: list[str] | None = None,
        force_change_pin: bool = False,
    ) -> None:
        self._native.set_min_pin_length(min_pin_length, rp_ids, force_change_pin)


class BioEnrollment(Closable):
    """BioEnrollment command facade with context-manager support.

    Usage::

        session = Ctap2Session(connection)
        with ClientPin(session) as client_pin:
            token = client_pin.get_pin_token(pin, permissions=0x08)
            protocol = client_pin.protocol
        with BioEnrollment(session, protocol, token) as bio:
            info = bio.get_fingerprint_sensor_info()
    """

    def __init__(
        self,
        session: Ctap2Session,
        protocol: PinProtocol,
        pin_token: bytes,
    ) -> None:
        self._session = session
        native = session._native
        if isinstance(native, _Ctap2SessionCcid):
            self._native: _BioEnrollmentCcid | _BioEnrollmentFido = _BioEnrollmentCcid(
                native, protocol._native, pin_token
            )
        else:
            self._native = _BioEnrollmentFido(native, protocol._native, pin_token)

    def close(self) -> None:
        """Restore the session so it can be reused."""
        native_session = self._session._native
        if isinstance(self._native, _BioEnrollmentCcid) and isinstance(
            native_session, _Ctap2SessionCcid
        ):
            self._native.close(native_session)
        elif isinstance(self._native, _BioEnrollmentFido) and isinstance(
            native_session, _Ctap2SessionFido
        ):
            self._native.close(native_session)

    def get_fingerprint_sensor_info(self) -> dict[int, Any]:
        return self._native.get_fingerprint_sensor_info()

    def enroll_begin(
        self,
        timeout: int | None = None,
        event: object | None = None,
        on_keepalive: object | None = None,
    ) -> dict[int, Any]:
        return self._native.enroll_begin(timeout, event, on_keepalive)

    def enroll_capture_next(
        self,
        template_id: bytes,
        timeout: int | None = None,
        event: object | None = None,
        on_keepalive: object | None = None,
    ) -> dict[int, Any]:
        return self._native.enroll_capture_next(
            template_id, timeout, event, on_keepalive
        )

    def enroll_cancel(self) -> None:
        self._native.enroll_cancel()

    def enumerate_enrollments(self) -> dict[int, Any]:
        return self._native.enumerate_enrollments()

    def set_name(self, template_id: bytes, name: str) -> None:
        self._native.set_name(template_id, name)

    def remove_enrollment(self, template_id: bytes) -> None:
        self._native.remove_enrollment(template_id)


class LargeBlobs(Closable):
    """Large Blobs command facade with context-manager support.

    Usage::

        session = Ctap2Session(connection)
        with ClientPin(session) as client_pin:
            token = client_pin.get_pin_token(pin, permissions=0x10)
            protocol = client_pin.protocol
        with LargeBlobs(session, protocol, token) as blobs:
            data = blobs.read_blob_array()
    """

    def __init__(
        self,
        session: Ctap2Session,
        protocol: PinProtocol,
        pin_token: bytes,
    ) -> None:
        self._session = session
        native = session._native
        if isinstance(native, _Ctap2SessionCcid):
            self._native: _LargeBlobsCcid | _LargeBlobsFido = _LargeBlobsCcid(
                native, protocol._native, pin_token
            )
        else:
            self._native = _LargeBlobsFido(native, protocol._native, pin_token)

    def close(self) -> None:
        """Restore the session so it can be reused."""
        native_session = self._session._native
        if isinstance(self._native, _LargeBlobsCcid) and isinstance(
            native_session, _Ctap2SessionCcid
        ):
            self._native.close(native_session)
        elif isinstance(self._native, _LargeBlobsFido) and isinstance(
            native_session, _Ctap2SessionFido
        ):
            self._native.close(native_session)

    def read_blob_array(self) -> bytes:
        return self._native.read_blob_array()

    def write_blob_array(self, data: bytes) -> None:
        self._native.write_blob_array(data)

    def get_blob(self, large_blob_key: bytes) -> bytes | None:
        """Get the decrypted blob for a single credential.

        :param large_blob_key: The largeBlobKey for the credential.
        :returns: The decrypted data, or None if no matching entry.
        """
        return self._native.get_blob(large_blob_key)

    def put_blob(self, large_blob_key: bytes, data: bytes) -> None:
        """Store a blob for a single credential.

        Replaces any existing entry for the same key.

        :param large_blob_key: The largeBlobKey for the credential.
        :param data: The data to store.
        """
        self._native.put_blob(large_blob_key, data)

    def delete_blob(self, large_blob_key: bytes) -> None:
        """Delete any blob(s) stored for a single credential.

        :param large_blob_key: The largeBlobKey for the credential.
        """
        self._native.delete_blob(large_blob_key)
