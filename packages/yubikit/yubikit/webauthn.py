# Copyright (c) 2026 Yubico AB
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

"""WebAuthn client facade.

Provides :class:`WebAuthnClient` which abstracts over FIDO HID and
SmartCard (CCID) transports, and the :class:`UserInteraction` and
:class:`ClientDataCollector` abstract base classes for caller-provided
callbacks.
"""

from __future__ import annotations

import abc
import logging

from _yubikit_native.sessions import WebAuthnCcidClient as _WebAuthnCcidClient
from _yubikit_native.sessions import WebAuthnClient as _WebAuthnClient

from .core import Closable
from .core.fido import FidoConnection
from .core.smartcard import SmartCardConnection
from .core.smartcard.scp import ScpKeyParams

logger = logging.getLogger(__name__)


class UserInteraction(abc.ABC):
    """Callbacks for user interaction during WebAuthn ceremonies.

    Implement this to handle PIN prompts, user-presence notifications,
    and user-verification decisions.
    """

    @abc.abstractmethod
    def prompt_up(self) -> None:
        """Called when the authenticator is waiting for user presence
        (touch)."""

    @abc.abstractmethod
    def request_pin(self, permissions: int, rp_id: str | None) -> str | None:
        """Called when a PIN is needed.

        :param permissions: Bitmask of requested PIN/UV permissions.
        :param rp_id: The RP ID for the request, if any.
        :return: The PIN string, or ``None`` to cancel the operation.
        """

    @abc.abstractmethod
    def request_uv(self, permissions: int, rp_id: str | None) -> bool:
        """Called when built-in user verification (e.g. biometrics) is
        available.

        :param permissions: Bitmask of requested PIN/UV permissions.
        :param rp_id: The RP ID for the request, if any.
        :return: ``True`` to proceed with UV, or ``False`` to fall
            back to PIN.
        """


class ClientDataCollector(abc.ABC):
    """Collects client data for WebAuthn ceremonies.

    Implement this to control how ``CollectedClientData`` is built and
    which RP ID is used for each request.
    """

    @abc.abstractmethod
    def collect_create(self, options_json: str) -> tuple[bytes, str]:
        """Collect client data for a registration request.

        :param options_json: JSON-encoded
            ``PublicKeyCredentialCreationOptions``.
        :return: A tuple of (client_data_json, rp_id) where
            client_data_json is the raw JSON bytes of the collected
            client data.
        """

    @abc.abstractmethod
    def collect_get(self, options_json: str) -> tuple[bytes, str]:
        """Collect client data for an authentication request.

        :param options_json: JSON-encoded
            ``PublicKeyCredentialRequestOptions``.
        :return: A tuple of (client_data_json, rp_id) where
            client_data_json is the raw JSON bytes of the collected
            client data.
        """


class WebAuthnClient(Closable):
    """WebAuthn client facade over SmartCard or FIDO HID transports.

    Performs registration (:meth:`make_credential`) and authentication
    (:meth:`get_assertion`) ceremonies, delegating PIN/UV interaction
    to the caller-provided :class:`UserInteraction` and client data
    collection to :class:`ClientDataCollector`.

    Usage::

        client = WebAuthnClient(connection, interaction, collector)
        reg_json = client.make_credential(options_json)
        assertions = client.get_assertion(options_json)
        client.close()
    """

    def __init__(
        self,
        connection: SmartCardConnection | FidoConnection,
        user_interaction: UserInteraction,
        client_data_collector: ClientDataCollector,
        scp_key_params: ScpKeyParams | None = None,
    ) -> None:
        if isinstance(connection, SmartCardConnection):
            self._native: _WebAuthnClient | _WebAuthnCcidClient = _WebAuthnCcidClient(
                connection,
                user_interaction,
                client_data_collector,
                scp_key_params=scp_key_params,
            )
        elif isinstance(connection, FidoConnection):
            if scp_key_params:
                raise ValueError("SCP can only be used with SmartCardConnection")
            self._native = _WebAuthnClient(
                connection,
                user_interaction,
                client_data_collector,
            )
        else:
            raise TypeError("Unsupported connection type")

        logger.debug("WebAuthn client initialized")

    def make_credential(self, options_json: str) -> str:
        """Perform a WebAuthn registration ceremony.

        :param options_json: JSON-encoded
            ``PublicKeyCredentialCreationOptions``.
        :return: JSON-encoded ``RegistrationResponse``.
        """
        return self._native.make_credential(options_json)

    def get_assertion(self, options_json: str) -> list[str]:
        """Perform a WebAuthn authentication ceremony.

        :param options_json: JSON-encoded
            ``PublicKeyCredentialRequestOptions``.
        :return: List of JSON-encoded ``AuthenticationResponse``
            objects, one per assertion.
        """
        return self._native.get_assertion(options_json)

    def close(self) -> None:
        """Close the client and release the underlying connection."""
        self._native.close()
