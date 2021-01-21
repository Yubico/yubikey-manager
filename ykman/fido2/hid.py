from __future__ import absolute_import

from .ctap import CtapDevice, CtapError, STATUS
from ._pyu2f import hidtransport

from enum import IntEnum, unique
from threading import Event
import struct


@unique
class CTAPHID(IntEnum):
    PING = 0x01
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11

    ERROR = 0x3F
    KEEPALIVE = 0x3B

    VENDOR_FIRST = 0x40


@unique
class CAPABILITY(IntEnum):
    WINK = 0x01
    LOCK = 0x02  # Not used
    CBOR = 0x04
    NMSG = 0x08

    def supported(self, flags):
        return bool(flags & self)


TYPE_INIT = 0x80


class _SingleEvent(object):
    def __init__(self):
        self.flag = False

    def is_set(self):
        if not self.flag:
            self.flag = True
            return False
        return True


class CtapHidDevice(CtapDevice):
    """
    CtapDevice implementation using the HID transport.

    :cvar descriptor: Device descriptor.
    """

    def __init__(self, descriptor, dev):
        self.descriptor = descriptor
        self._dev = dev

    def __repr__(self):
        return "CtapHidDevice(%s)" % self.descriptor["path"]

    @property
    def version(self):
        """CTAP HID protocol version.

        :rtype: int
        """
        return self._dev.u2fhid_version

    @property
    def device_version(self):
        """Device version number."""
        return self._dev.device_version

    @property
    def capabilities(self):
        """Capabilities supported by the device."""
        return self._dev.capabilities

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        event = event or Event()
        self._dev.InternalSend(TYPE_INIT | cmd, bytearray(data))
        last_ka = None
        while not event.is_set():
            status, resp = self._dev.InternalRecv()
            status ^= TYPE_INIT
            if status == cmd:
                return bytes(resp)
            elif status == CTAPHID.ERROR:
                raise CtapError(resp[0])
            elif status == CTAPHID.KEEPALIVE:
                ka_status = resp[0]
                if on_keepalive and last_ka != ka_status:
                    try:
                        ka_status = STATUS(ka_status)
                    except ValueError:
                        pass  # Unknown status value
                    last_ka = ka_status
                    on_keepalive(ka_status)
                continue
            else:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)

        # Cancel the request.
        self._dev.InternalSend(TYPE_INIT | CTAPHID.CANCEL, bytearray())
        self._dev.InternalRecv()
        raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)

    def wink(self):
        """Causes the authenticator to blink."""
        self.call(CTAPHID.WINK)

    def ping(self, msg=b"Hello FIDO"):
        """Sends data to the authenticator, which echoes it back.

        :param msg: The data to send.
        :return: The response from the authenticator.
        """
        return self.call(CTAPHID.PING, msg)

    def lock(self, lock_time=10):
        """Locks the channel."""
        self.call(CTAPHID.LOCK, struct.pack(">B", lock_time))

    def close(self):
        del self._dev
        del self.descriptor

    @classmethod
    def list_devices(cls, selector=hidtransport.HidUsageSelector):
        for d in hidtransport.hid.Enumerate():
            if selector(d):
                try:
                    dev = hidtransport.hid.Open(d["path"])
                    yield cls(d, hidtransport.UsbHidTransport(dev))
                except OSError:
                    # Insufficient permissions to access device
                    pass
