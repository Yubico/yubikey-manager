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

from yubikit.core import Connection, PID, TRANSPORT, YUBIKEY
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import (
    DeviceInfo,
    USB_INTERFACE,
)
from yubikit.support import read_info
from .base import YkmanDevice
from .hid import (
    list_otp_devices as _list_otp_devices,
    list_ctap_devices as _list_ctap_devices,
)
from .pcsc import list_devices as _list_ccid_devices
from smartcard.pcsc.PCSCExceptions import EstablishContextException
from smartcard.Exceptions import NoCardException

from time import sleep, time
from collections import Counter
from typing import (
    Dict,
    Mapping,
    List,
    Tuple,
    Iterable,
    Type,
    Hashable,
    Set,
)
import sys
import ctypes
import logging

logger = logging.getLogger(__name__)


def _warn_once(message, e_type=Exception):
    warned: List[bool] = []

    def outer(f):
        def inner():
            try:
                return f()
            except e_type:
                if not warned:
                    logger.warning(message)
                    warned.append(True)
                raise

        return inner

    return outer


@_warn_once(
    "PC/SC not available. Smart card (CCID) protocols will not function.",
    EstablishContextException,
)
def list_ccid_devices():
    """List CCID devices."""
    return _list_ccid_devices()


@_warn_once("No CTAP HID backend available. FIDO protocols will not function.")
def list_ctap_devices():
    """List CTAP devices."""
    return _list_ctap_devices()


@_warn_once("No OTP HID backend available. OTP protocols will not function.")
def list_otp_devices():
    """List OTP devices."""
    return _list_otp_devices()


_CONNECTION_LIST_MAPPING = {
    SmartCardConnection: list_ccid_devices,
    OtpConnection: list_otp_devices,
    FidoConnection: list_ctap_devices,
}


def scan_devices() -> Tuple[Mapping[PID, int], int]:
    """Scan USB for attached YubiKeys, without opening any connections.

    :return: A dict mapping PID to device count, and a state object which can be used to
        detect changes in attached devices.
    """
    fingerprints = set()
    merged: Dict[PID, int] = {}
    for list_devs in _CONNECTION_LIST_MAPPING.values():
        try:
            devs = list_devs()
        except Exception:
            logger.debug("Device listing error", exc_info=True)
            devs = []
        merged.update(Counter(d.pid for d in devs if d.pid is not None))
        fingerprints.update({d.fingerprint for d in devs})
    if sys.platform == "win32" and not bool(ctypes.windll.shell32.IsUserAnAdmin()):
        from .hid.windows import list_paths

        counter: Counter[PID] = Counter()
        for pid, path in list_paths():
            if pid not in merged:
                try:
                    counter[PID(pid)] += 1
                    fingerprints.add(path)
                except ValueError:  # Unsupported PID
                    logger.debug(f"Unsupported Yubico device with PID: {pid:02x}")
        merged.update(counter)
    return merged, hash(tuple(fingerprints))


class _PidGroup:
    def __init__(self, pid):
        self._pid = pid
        self._infos: Dict[Hashable, DeviceInfo] = {}
        self._resolved: Dict[Hashable, Dict[USB_INTERFACE, YkmanDevice]] = {}
        self._unresolved: Dict[USB_INTERFACE, List[YkmanDevice]] = {}
        self._devcount: Dict[USB_INTERFACE, int] = Counter()
        self._fingerprints: Set[Hashable] = set()
        self._ctime = time()

    def _key(self, info):
        return (
            info.serial,
            info.version,
            info.form_factor,
            str(info.supported_capabilities),
            info.config.get_bytes(False),
            info.is_locked,
            info.is_fips,
            info.is_sky,
        )

    def add(self, conn_type, dev, force_resolve=False):
        logger.debug(f"Add device for {conn_type}: {dev}")
        iface = conn_type.usb_interface
        self._fingerprints.add(dev.fingerprint)
        self._devcount[iface] += 1
        if force_resolve or len(self._resolved) < max(self._devcount.values()):
            try:
                with dev.open_connection(conn_type) as conn:
                    info = read_info(conn, dev.pid)
                key = self._key(info)
                self._infos[key] = info
                self._resolved.setdefault(key, {})[iface] = dev
                logger.debug(f"Resolved device {info.serial}")
                return
            except Exception:
                logger.warning("Failed opening device", exc_info=True)
        self._unresolved.setdefault(iface, []).append(dev)

    def supports_connection(self, conn_type):
        return conn_type.usb_interface in self._devcount

    def connect(self, key, conn_type):
        iface = conn_type.usb_interface

        resolved = self._resolved[key].get(iface)
        if resolved:
            return resolved.open_connection(conn_type)

        devs = self._unresolved.get(iface, [])
        failed = []
        try:
            while devs:
                dev = devs.pop()
                try:
                    conn = dev.open_connection(conn_type)
                    info = read_info(conn, dev.pid)
                    dev_key = self._key(info)
                    if dev_key in self._infos:
                        self._resolved.setdefault(dev_key, {})[iface] = dev
                        logger.debug(f"Resolved device {info.serial}")
                        if dev_key == key:
                            return conn
                    elif self._pid.yubikey_type == YUBIKEY.NEO and not devs:
                        self._resolved.setdefault(key, {})[iface] = dev
                        logger.debug("Resolved last NEO device without serial")
                        return conn
                    conn.close()
                except Exception:
                    logger.warning("Failed opening device", exc_info=True)
                    failed.append(dev)
        finally:
            devs.extend(failed)

        if self._devcount[iface] < len(self._infos):
            logger.debug(f"Checking for more devices over {iface!s}")
            for dev in _CONNECTION_LIST_MAPPING[conn_type]():
                if self._pid == dev.pid and dev.fingerprint not in self._fingerprints:
                    self.add(conn_type, dev, True)

            resolved = self._resolved[key].get(iface)
            if resolved:
                return resolved.open_connection(conn_type)

        # Retry if we are within a 5 second period after creation,
        # as not all USB interface become usable at the exact same time.
        if time() < self._ctime + 5:
            logger.debug("Device not found, retry in 1s")
            sleep(1.0)
            return self.connect(key, conn_type)

        raise ValueError("Failed to connect to the device")

    def get_devices(self):
        results = []
        for key, info in self._infos.items():
            dev = next(iter(self._resolved[key].values()))
            results.append(
                (_UsbCompositeDevice(self, key, dev.fingerprint, dev.pid), info)
            )
        return results


class _UsbCompositeDevice(YkmanDevice):
    def __init__(self, group, key, fingerprint, pid):
        super().__init__(TRANSPORT.USB, fingerprint, pid)
        self._group = group
        self._key = key

    def supports_connection(self, connection_type):
        return self._group.supports_connection(connection_type)

    def open_connection(self, connection_type):
        if not self.supports_connection(connection_type):
            raise ValueError("Unsupported Connection type")

        # Allow for ~3s reclaim time on NEO for CCID
        assert self.pid  # nosec
        if self.pid.yubikey_type == YUBIKEY.NEO and issubclass(
            connection_type, SmartCardConnection
        ):
            for _ in range(6):
                try:
                    return self._group.connect(self._key, connection_type)
                except (NoCardException, ValueError):
                    sleep(0.5)

        return self._group.connect(self._key, connection_type)


def list_all_devices(
    connection_types: Iterable[Type[Connection]] = _CONNECTION_LIST_MAPPING.keys(),
) -> List[Tuple[YkmanDevice, DeviceInfo]]:
    """Connect to all attached YubiKeys and read device info from them.

    :param connection_types: An iterable of YubiKey connection types.
    :return: A list of (device, info) tuples for each connected device.
    """
    groups: Dict[PID, _PidGroup] = {}

    for connection_type in connection_types:
        for base_type in _CONNECTION_LIST_MAPPING:
            if issubclass(connection_type, base_type):
                connection_type = base_type
                break
        else:
            raise ValueError("Invalid connection type")
        try:
            for dev in _CONNECTION_LIST_MAPPING[connection_type]():
                group = groups.setdefault(dev.pid, _PidGroup(dev.pid))
                group.add(connection_type, dev)
        except Exception:
            logger.exception("Unable to list devices for connection")
    devices = []
    for group in groups.values():
        devices.extend(group.get_devices())
    return devices
