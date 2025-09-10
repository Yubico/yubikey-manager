import logging

from fido2.hid import CtapHidDevice, list_descriptors, open_connection

from yubikit.core import PID, TRANSPORT, Connection
from yubikit.support import read_info

from ..base import REINSERT_STATUS, CancelledException, YkmanDevice
from ..fido import FidoConnection

logger = logging.getLogger(__name__)


class CtapYubiKeyDevice(YkmanDevice):
    """YubiKey FIDO USB HID device"""

    def __init__(self, descriptor):
        super().__init__(TRANSPORT.USB, descriptor.path, PID(descriptor.pid))
        self.descriptor = descriptor

    def supports_connection(self, connection_type):
        return issubclass(CtapHidDevice, connection_type)

    def open_connection(self, connection_type):
        assert isinstance(connection_type, type)  # noqa: S101
        if self.supports_connection(connection_type):
            dev = CtapHidDevice(self.descriptor, open_connection(self.descriptor))
            assert isinstance(dev, Connection)  # noqa: S101
            return dev
        return super().open_connection(connection_type)

    def _do_reinsert(self, reinsert_cb, event):
        removed_state = None
        with self.open_connection(FidoConnection) as conn:
            assert isinstance(conn, Connection)  # noqa: S101
            info = read_info(conn, self.pid)

        reinsert_cb(REINSERT_STATUS.REMOVE)
        logger.debug(f"Waiting for removal of device {self.fingerprint}")
        while not event.wait(0.5):
            keys = list_ctap_devices()
            present = {k.fingerprint for k in keys}
            if removed_state is None:
                if self.fingerprint not in present:
                    logger.debug(f"Removed! {self.fingerprint}")
                    reinsert_cb(REINSERT_STATUS.REINSERT)
                    removed_state = present
            else:
                added = present - removed_state
                if len(added) == 1:
                    dev_fp = next(iter(added))  # Path may have changed
                    logger.debug(f"Inserted! {dev_fp}")
                    key = next(k for k in keys if k.fingerprint == dev_fp)
                    # Update fingerprint and descriptor
                    self._fingerprint = key.fingerprint
                    self.descriptor = key.descriptor
                    with self.open_connection(FidoConnection) as conn:
                        assert isinstance(conn, Connection)  # noqa: S101
                        info2 = read_info(conn, self.pid)
                    if info.serial != info2.serial or info.version != info2.version:
                        raise ValueError(
                            "Reinserted YubiKey does not match the original"
                        )
                    return
                elif len(added) > 1:
                    raise ValueError("Multiple YubiKeys inserted")

        raise CancelledException()


def list_ctap_devices() -> list[CtapYubiKeyDevice]:
    devs = []
    for desc in list_descriptors():
        if desc.vid == 0x1050:
            try:
                devs.append(CtapYubiKeyDevice(desc))
            except ValueError:
                logger.debug(f"Unsupported Yubico device with PID: {desc.pid:02x}")
    return devs
