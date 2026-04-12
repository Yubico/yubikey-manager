# Copyright (c) 2015-2020 Yubico AB
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

import abc
from enum import Enum
from threading import Event
from typing import Callable, Hashable

from yubikit.core import PID, TRANSPORT, YubiKeyDevice


class REINSERT_STATUS(Enum):
    REMOVE = 1
    REINSERT = 2


class CancelledException(Exception):
    """Raised when the caller cancels an operation."""


class YkmanDevice(YubiKeyDevice):
    """YubiKey device reference, with optional PID"""

    def __init__(self, transport: TRANSPORT, fingerprint: Hashable, pid: PID | None):
        super(YkmanDevice, self).__init__(transport, fingerprint)
        self._pid = pid

    @property
    def pid(self) -> PID | None:
        """Return the PID of the YubiKey, if available."""
        return self._pid

    def reinsert(
        self,
        reinsert_cb: Callable[[REINSERT_STATUS], None] | None = None,
        event: Event | None = None,
    ) -> None:
        """Wait for the user to remove and reinsert the YubiKey.

        This may be required to perform certain operations, such as FIDO reset.

        This method will attempt to verify that the same YubiKey is reinserted,
        but it will only fail when this is definitely not the case (eg. if the serial
        number does not match).

        :param reinsert_cb: Callback to indicate the the YubiKey has been removed,
        and should be reinserted.
        :param event: Optional event to cancel (throws CancelledException).
        """
        self._do_reinsert(reinsert_cb or (lambda _: None), event or Event())

    @abc.abstractmethod
    def _do_reinsert(
        self, reinsert_cb: Callable[[REINSERT_STATUS], None], event: Event
    ) -> None:
        pass

    def __repr__(self):
        return "%s(pid=%04x, fingerprint=%r)" % (
            type(self).__name__,
            self.pid or 0,
            self.fingerprint,
        )
