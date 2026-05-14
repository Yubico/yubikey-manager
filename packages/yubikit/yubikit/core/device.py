import abc
from enum import Enum
from threading import Event
from typing import Callable, Hashable, TypeVar

from ..management import DeviceInfo
from . import PID, TRANSPORT, Connection


class REINSERT_STATUS(Enum):
    REMOVE = 1
    REINSERT = 2


T_Connection = TypeVar("T_Connection", bound=Connection)


class YubiKeyDevice(abc.ABC):
    """YubiKey device reference"""

    @property
    @abc.abstractmethod
    def transport(self) -> TRANSPORT:
        """Get the transport used to communicate with this YubiKey"""

    @property
    @abc.abstractmethod
    def pid(self) -> PID | None:
        """Return the PID of the YubiKey, if available."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Get the product name of this YubiKey"""

    @property
    @abc.abstractmethod
    def info(self) -> DeviceInfo:
        """Get the DeviceInfo for this YubiKey"""

    def supports_connection(self, connection_type: type[Connection]) -> bool:
        """Check if a YubiKeyDevice supports a specific Connection type"""
        return False

    # mypy will not accept abstract types in type[T_Connection]
    def open_connection(
        self, connection_type: type[T_Connection] | Callable[..., T_Connection]
    ) -> T_Connection:
        """Opens a connection to the YubiKey"""
        raise ValueError("Unsupported Connection type")

    @property
    @abc.abstractmethod
    def fingerprint(self) -> Hashable:
        """Used to identify that device references from different enumerations represent
        the same physical YubiKey. This fingerprint is not stable between sessions, or
        after un-plugging, and re-plugging a device."""

    @abc.abstractmethod
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

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.fingerprint == other.fingerprint

    def __hash__(self):
        return hash(self.fingerprint)

    def __repr__(self):
        return "%s(pid=%04x, fingerprint=%r)" % (
            type(self).__name__,
            self.pid or 0,
            self.fingerprint,
        )
