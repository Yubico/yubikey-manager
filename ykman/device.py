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

from yubikit.core import (
    AID,
    TRANSPORT,
    Version,
    Connection,
    NotSupportedError,
    ApplicationNotAvailableError,
)
from yubikit.core.otp import OtpConnection, CommandRejectedError
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import (
    SmartCardConnection,
    SmartCardProtocol,
)
from yubikit.management import (
    ManagementSession,
    DeviceInfo,
    DeviceConfig,
    USB_INTERFACE,
    CAPABILITY,
    FORM_FACTOR,
)
from yubikit.yubiotp import YubiOtpSession
from .base import PID, YUBIKEY, YkmanDevice
from .hid import list_otp_devices, list_ctap_devices
from .pcsc import list_devices as _list_ccid_devices
from smartcard.pcsc.PCSCExceptions import EstablishContextException
from smartcard.Exceptions import NoCardException

from time import sleep
from collections import Counter
from typing import Dict, Mapping, List, Tuple, Optional, Iterable, Type
import sys
import ctypes
import logging

logger = logging.getLogger(__name__)


_pcsc_missing = False


def list_ccid_devices():
    try:
        return _list_ccid_devices()
    except Exception as e:
        global _pcsc_missing
        if not _pcsc_missing and isinstance(e, EstablishContextException):
            _pcsc_missing = True
            print(
                "WARNING: PCSC not available. Smart card protocols will not function.",
                file=sys.stderr,
            )
        logger.error("Unable to list CCID devices", exc_info=e)
        return []


def is_fips_version(version: Version) -> bool:
    """True if a given firmware version indicates a YubiKey FIPS"""
    return (4, 4, 0) <= version < (4, 5, 0)


BASE_NEO_APPS = CAPABILITY.OTP | CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP

CONNECTION_LIST_MAPPING = {
    SmartCardConnection: list_ccid_devices,
    OtpConnection: list_otp_devices,
    FidoConnection: list_ctap_devices,
}


def scan_devices() -> Tuple[Mapping[PID, int], int]:
    """Scan USB for attached YubiKeys, without opening any connections.

    Returns a dict mapping PID to device count, and a state object which can be used to
    detect changes in attached devices.
    """
    fingerprints = set()
    merged: Dict[PID, int] = {}
    for list_devs in CONNECTION_LIST_MAPPING.values():
        devs = list_devs()
        merged.update(Counter(d.pid for d in devs if d.pid is not None))
        fingerprints.update({d.fingerprint for d in devs})
    if sys.platform == "win32" and not bool(ctypes.windll.shell32.IsUserAnAdmin()):
        from .hid.windows import list_paths

        counter = Counter()
        for pid, path in list_paths():
            if pid not in merged:
                try:
                    counter[PID(pid)] += 1
                    fingerprints.add(path)
                except ValueError:  # Unsupported PID
                    logger.debug(f"Unsupported Yubico device with PID: {pid:02x}")
        merged.update(counter)
    return merged, hash(tuple(fingerprints))


def list_all_devices() -> List[Tuple[YkmanDevice, DeviceInfo]]:
    """Connects to all attached YubiKeys and reads device info from them.

    Returns a list of (device, info) tuples for each connected device.
    """
    handled_pids = set()
    pids: Dict[PID, bool] = {}
    devices = []

    for connection_type, list_devs in CONNECTION_LIST_MAPPING.items():
        for dev in list_devs():
            if dev.pid not in handled_pids and pids.get(dev.pid, True):
                try:
                    with dev.open_connection(connection_type) as conn:
                        info = read_info(dev.pid, conn)
                    pids[dev.pid] = True
                    devices.append((dev, info))
                except Exception as e:
                    pids[dev.pid] = False
                    logger.error("Failed opening device", exc_info=e)
        handled_pids.update({pid for pid, handled in pids.items() if handled})

    return devices


def connect_to_device(
    serial: Optional[int] = None,
    connection_types: Iterable[Type[Connection]] = CONNECTION_LIST_MAPPING.keys(),
) -> Tuple[Connection, YkmanDevice, DeviceInfo]:
    """Looks for a YubiKey to connect to.

    :param serial: Used to filter devices by serial number, if present.
    :param connection_types: Filter connection types.
    :return: An open connection to the device, the device reference, and the device
        information read from the device.
    """
    retry_ccid = []
    for connection_type in connection_types:
        for dev in CONNECTION_LIST_MAPPING[connection_type]():
            try:
                conn = dev.open_connection(connection_type)
            except NoCardException:
                retry_ccid.append(dev)
                logger.debug("CCID No card present, will retry")
                continue
            info = read_info(dev.pid, conn)
            if serial and info.serial != serial:
                conn.close()
            else:
                return conn, dev, info

    # NEO ejects the card when other interfaces are used, and returns it after ~3s.
    for _ in range(6):
        if not retry_ccid:
            break
        sleep(0.5)
        for dev in retry_ccid[:]:
            try:
                conn = dev.open_connection(SmartCardConnection)
            except NoCardException:
                continue
            retry_ccid.remove(dev)
            info = read_info(dev.pid, conn)
            if serial and info.serial != serial:
                conn.close()
            else:
                return conn, dev, info

    if serial:
        raise ValueError("YubiKey with given serial not found")
    raise ValueError("No YubiKey found with the given interface(s)")


def _otp_read_data(conn):
    otp = YubiOtpSession(conn)
    version = otp.version
    try:
        serial = otp.get_serial()
    except Exception as e:
        logger.debug("Unable to read serial over OTP, no serial", exc_info=e)
        serial = None
    return version, serial


AID_U2F_YUBICO = b"\xa0\x00\x00\x05\x27\x10\x02"  # Old U2F AID

SCAN_APPLETS = {
    # AID.OTP: CAPABILITY.OTP,  # NB: OTP will be checked elsewhere
    AID.FIDO: CAPABILITY.U2F,
    AID_U2F_YUBICO: CAPABILITY.U2F,
    AID.PIV: CAPABILITY.PIV,
    AID.OPENPGP: CAPABILITY.OPENPGP,
    AID.OATH: CAPABILITY.OATH,
}


def _read_info_ccid(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        version = mgmt.version
        try:
            return mgmt.read_device_info()
        except NotSupportedError:
            # Workaround to "de-select" the Management Applet needed for NEO
            conn.send_and_receive(b"\xa4\x04\x00\x08")
    except ApplicationNotAvailableError:
        logger.debug("Unable to select Management application, use fallback.")
        version = None

    # Synthesize data
    capabilities = CAPABILITY(0)

    # Try to read serial (and version if needed) from OTP application
    try:
        otp_version, serial = _otp_read_data(conn)
        capabilities |= CAPABILITY.OTP
        if version is None:
            version = otp_version
    except ApplicationNotAvailableError:
        logger.debug("Unable to select OTP application")
        serial = None

    if version is None:
        version = (3, 0, 0)  # Guess, no way to know

    # Scan for remaining capabilities
    protocol = SmartCardProtocol(conn)
    for aid, code in SCAN_APPLETS.items():
        try:
            logger.debug("Check for %s", code)
            protocol.select(aid)
            capabilities |= code
            logger.debug("Found applet: aid: %s, capability: %s", aid, code)
        except ApplicationNotAvailableError:
            logger.debug("Missing applet: aid: %s, capability: %s", aid, code)
        except Exception as e:
            logger.error(
                "Error selecting aid: %s, capability: %s", aid, code, exc_info=e,
            )

    # Assume U2F on devices >= 3.3.0
    if USB_INTERFACE.FIDO in interfaces or version >= (3, 3, 0):
        capabilities |= CAPABILITY.U2F

    return DeviceInfo(
        config=DeviceConfig(
            enabled_capabilities={},  # Populated later
            auto_eject_timeout=0,
            challenge_response_timeout=0,
            device_flags=0,
        ),
        serial=serial,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_capabilities={
            TRANSPORT.USB: capabilities,
            TRANSPORT.NFC: capabilities,
        },
        is_locked=False,
    )


def _read_info_otp(conn, key_type, interfaces):
    otp = None
    serial = None

    try:
        mgmt = ManagementSession(conn)
    except ApplicationNotAvailableError:
        otp = YubiOtpSession(conn)

    # Retry during potential reclaim timeout period (~3s).
    for _ in range(8):
        try:
            if otp is None:
                try:
                    return mgmt.read_device_info()  # Rejected while reclaim
                except NotSupportedError:
                    otp = YubiOtpSession(conn)
            serial = otp.get_serial()  # Rejected if reclaim (or not API_SERIAL_VISIBLE)
            break
        except CommandRejectedError:
            sleep(0.5)  # Potential reclaim
    else:
        otp = YubiOtpSession(conn)

    # Synthesize info
    logger.debug("Unable to get info via Management application, use fallback")

    version = otp.version
    if key_type == YUBIKEY.NEO:
        usb_supported = BASE_NEO_APPS
        if USB_INTERFACE.FIDO in interfaces or version >= (3, 3, 0):
            usb_supported |= CAPABILITY.U2F
        capabilities = {
            TRANSPORT.USB: usb_supported,
            TRANSPORT.NFC: usb_supported,
        }
    elif key_type == YUBIKEY.YKP:
        capabilities = {
            TRANSPORT.USB: CAPABILITY.OTP | TRANSPORT.U2F,
        }
    else:
        capabilities = {
            TRANSPORT.USB: CAPABILITY.OTP,
        }

    return DeviceInfo(
        config=DeviceConfig(
            enabled_capabilities={},  # Populated later
            auto_eject_timeout=0,
            challenge_response_timeout=0,
            device_flags=0,
        ),
        serial=serial,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_capabilities=capabilities.copy(),
        is_locked=False,
    )


def _read_info_ctap(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        return mgmt.read_device_info()
    except Exception:  # SKY 1 or NEO
        version = (3, 0, 0)  # Guess, no way to know

        supported_apps = {TRANSPORT.USB: CAPABILITY.U2F}
        if key_type == YUBIKEY.NEO:
            supported_apps[TRANSPORT.USB] |= BASE_NEO_APPS
            supported_apps[TRANSPORT.NFC] = supported_apps[TRANSPORT.USB]

        return DeviceInfo(
            config=DeviceConfig(
                enabled_capabilities={},  # Populated later
                auto_eject_timeout=0,
                challenge_response_timeout=0,
                device_flags=0,
            ),
            serial=None,
            version=version,
            form_factor=FORM_FACTOR.USB_A_KEYCHAIN,
            supported_capabilities=supported_apps,
            is_locked=False,
        )


def read_info(pid: Optional[PID], conn: Connection) -> DeviceInfo:
    """Read out a DeviceInfo object from a YubiKey, or attempt to synthesize one."""
    if pid:
        key_type: Optional[YUBIKEY] = pid.get_type()
        interfaces = pid.get_interfaces()
    else:  # No PID for NFC connections
        key_type = None
        interfaces = USB_INTERFACE(0)

    if isinstance(conn, SmartCardConnection):
        info = _read_info_ccid(conn, key_type, interfaces)
    elif isinstance(conn, OtpConnection):
        info = _read_info_otp(conn, key_type, interfaces)
    elif isinstance(conn, FidoConnection):
        info = _read_info_ctap(conn, key_type, interfaces)
    else:
        raise TypeError("Invalid connection type")

    logger.debug("Read info: %s", info)

    # Set usb_enabled if missing (pre YubiKey 5)
    if (
        info.has_transport(TRANSPORT.USB)
        and TRANSPORT.USB not in info.config.enabled_capabilities
    ):
        usb_enabled = info.supported_capabilities[TRANSPORT.USB]
        if usb_enabled == (CAPABILITY.OTP | CAPABILITY.U2F | USB_INTERFACE.CCID):
            # YubiKey Edge, hide unusable CCID interface
            usb_enabled = CAPABILITY.OTP | CAPABILITY.U2F
            info.supported_capabilities = {TRANSPORT.USB: usb_enabled}

        if USB_INTERFACE.OTP not in interfaces:
            usb_enabled &= ~CAPABILITY.OTP
        if USB_INTERFACE.FIDO not in interfaces:
            usb_enabled &= ~(CAPABILITY.U2F | CAPABILITY.FIDO2)
        if USB_INTERFACE.CCID not in interfaces:
            usb_enabled &= ~(
                USB_INTERFACE.CCID
                | CAPABILITY.OATH
                | CAPABILITY.OPENPGP
                | CAPABILITY.PIV
            )
        info.config.enabled_capabilities[TRANSPORT.USB] = usb_enabled

    # Set nfc_enabled if missing (pre YubiKey 5)
    if (
        info.has_transport(TRANSPORT.NFC)
        and TRANSPORT.NFC not in info.config.enabled_capabilities
    ):
        info.config.enabled_capabilities[TRANSPORT.NFC] = info.supported_capabilities[
            TRANSPORT.NFC
        ]

    # Workaround for invalid configurations.
    # Assume all form factors except USB_A_KEYCHAIN and
    # USB_C_KEYCHAIN >= 5.2.4 does not support NFC.
    if not (
        info.version < (4, 0, 0)  # No relevant programming yet
        or (info.form_factor is FORM_FACTOR.USB_A_KEYCHAIN)
        or (
            info.form_factor is FORM_FACTOR.USB_C_KEYCHAIN and info.version >= (5, 2, 4)
        )
    ):
        info.supported_capabilities = {
            TRANSPORT.USB: info.supported_capabilities[TRANSPORT.USB]
        }
        info.config.enabled_capabilities = {
            TRANSPORT.USB: info.config.enabled_capabilities[TRANSPORT.USB]
        }

    return info


def _fido_only(capabilities):
    return capabilities & ~(CAPABILITY.U2F | CAPABILITY.FIDO2) == 0


def _is_preview(version):
    _PREVIEW_RANGES = (
        ((5, 0, 0), (5, 1, 0)),
        ((5, 2, 0), (5, 2, 3)),
        ((5, 5, 0), (5, 5, 2)),
    )
    for start, end in _PREVIEW_RANGES:
        if start <= version < end:
            return True
    return False


def get_name(info: DeviceInfo, key_type: Optional[YUBIKEY]) -> str:
    """Determine the product name of a YubiKey"""
    usb_supported = info.supported_capabilities[TRANSPORT.USB]
    if not key_type:
        if info.serial is None and _fido_only(usb_supported):
            key_type = YUBIKEY.SKY
        elif info.version[0] == 3:
            key_type = YUBIKEY.NEO
        else:
            key_type = YUBIKEY.YK4

    device_name = key_type.value

    if key_type == YUBIKEY.SKY:
        if CAPABILITY.FIDO2 not in usb_supported:
            device_name = "FIDO U2F Security Key"  # SKY 1
        if info.has_transport(TRANSPORT.NFC):
            device_name = "Security Key NFC"
    elif key_type == YUBIKEY.YK4:
        if info.version[0] == 0:
            return "Yubikey (%d.%d.%d)" % info.version
        if _is_preview(info.version):
            device_name = "YubiKey Preview"
        elif is_fips_version(info.version):
            device_name = "YubiKey FIPS"
        elif usb_supported == CAPABILITY.OTP | CAPABILITY.U2F:
            device_name = "YubiKey Edge"
        elif info.version >= (5, 1, 0):
            if info.form_factor in (FORM_FACTOR.USB_A_BIO, FORM_FACTOR.USB_C_BIO):
                device_name = "YubiKey "
                if info.form_factor == FORM_FACTOR.USB_C_BIO:
                    device_name += "C "
                device_name += "BIO"
                if _fido_only(usb_supported):
                    device_name += " (FIDO Edition)"
            else:
                device_name = "YubiKey 5"
                if info.form_factor == FORM_FACTOR.USB_A_KEYCHAIN:
                    if info.has_transport(TRANSPORT.NFC):
                        device_name += " NFC"
                    else:
                        device_name += "A"
                elif info.form_factor == FORM_FACTOR.USB_A_NANO:
                    device_name += " Nano"
                elif info.form_factor == FORM_FACTOR.USB_C_KEYCHAIN:
                    device_name += "C"
                    if info.has_transport(TRANSPORT.NFC):
                        device_name += " NFC"
                elif info.form_factor == FORM_FACTOR.USB_C_NANO:
                    device_name += "C Nano"
                elif info.form_factor == FORM_FACTOR.USB_C_LIGHTNING:
                    device_name += "Ci"

    return device_name
