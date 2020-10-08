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
    PID,
    TRANSPORT,
    USB_INTERFACE,
    APPLICATION,
    FORM_FACTOR,
    YUBIKEY,
    Version,
    Connection,
    NotSupportedError,
    ApplicationNotAvailableError,
)
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import (
    SmartCardConnection,
    SmartCardProtocol,
)
from yubikit.management import ManagementSession, DeviceInfo, DeviceConfig
from yubikit.yubiotp import YubiOtpSession
from fido2.ctap import CtapDevice
from .hid import list_otp_devices, list_ctap_devices
from .scard import list_devices as _list_ccid_devices

from collections import Counter
from typing import Dict, Mapping, List, Tuple, Optional, Hashable
import logging

logger = logging.getLogger(__name__)


def list_ccid_devices():
    try:
        return _list_ccid_devices()
    except Exception as e:
        logger.error("Unable to list CCID devices", exc_info=e)
        return []


def is_fips_version(version: Version) -> bool:
    """True if a given firmware version indicates a YubiKey FIPS"""
    return (4, 4, 0) <= version < (4, 5, 0)


BASE_NEO_APPS = APPLICATION.OTP | APPLICATION.OATH | APPLICATION.PIV | APPLICATION.OPGP


def scan_devices() -> Tuple[Mapping[PID, int], Hashable]:
    """Scan for attached YubiKeys, without opening any connections.

    Returns a dict mapping PID to device count, and a state object which can be used to
    detect changes in attached devices.
    """
    # Scans all attached devices, without opening any connections.
    otp_devs = list_otp_devices()
    ctap_devs = list_ctap_devices()
    ccid_devs = list_ccid_devices()

    # Avoid counting devices twice over different interfaces.
    merged: Dict[PID, int] = {}
    merged.update(Counter(d.pid for d in otp_devs if d.pid is not None))
    merged.update(Counter(d.pid for d in ctap_devs if d.pid is not None))
    merged.update(Counter(d.pid for d in ccid_devs if d.pid is not None))

    state = tuple(
        {d.fingerprint for devs in (otp_devs, ctap_devs, ccid_devs) for d in devs}
    )
    return merged, state


def list_all_devices() -> List[Tuple[PID, DeviceInfo]]:
    """Connects to all attached YubiKeys and reads device info from them.

    Returns a list of (PID, info) tuples for each connected device.
    """
    # List all attached devices, returning pid and info for each.
    handled_pids = set()
    pids: Dict[PID, bool] = {}
    devices = []

    def handle(dev, get_connection):
        if dev.pid not in handled_pids and pids.get(dev.pid, True):
            try:
                with get_connection() as conn:
                    info = read_info(dev.pid, conn)
                pids[dev.pid] = True
                devices.append((dev.pid, info))
            except Exception as e:
                pids[dev.pid] = False
                logger.error("Failed opening device", exc_info=e)

    # Handle OTP devices
    for otp in list_otp_devices():
        handle(otp, otp.open_otp_connection)
    handled_pids.update({pid for pid, handled in pids.items() if handled})

    # Handle CCID devices
    for ccid in list_ccid_devices():
        handle(ccid, ccid.open_smartcard_connection)
    handled_pids.update({pid for pid, handled in pids.items() if handled})

    # Handle FIDO devices
    for ctap in list_ctap_devices():
        handle(ctap, ctap.open_ctap_connection)
    handled_pids.update({pid for pid, handled in pids.items() if handled})

    return devices


def connect_to_device(
    serial: Optional[int] = None,
    interfaces: USB_INTERFACE = USB_INTERFACE(sum(USB_INTERFACE)),
) -> Tuple[Connection, PID, DeviceInfo]:
    """Get a connection to a YubiKey using one of the provided interfaces.

    Returns a tuple of (connection, pid, info) for the device.
    """
    interfaces = USB_INTERFACE(interfaces)
    if USB_INTERFACE.CCID in interfaces:
        for dev in list_ccid_devices():
            try:
                conn = dev.open_smartcard_connection()
                info = read_info(dev.pid, conn)
                if serial and info.serial != serial:
                    conn.close()
                else:
                    return conn, dev.pid, info
            except Exception as e:
                logger.debug("Error connecting", exc_info=e)

    if USB_INTERFACE.OTP in interfaces:
        for dev in list_otp_devices():
            try:
                conn = dev.open_otp_connection()
                info = read_info(dev.pid, conn)
                if serial and info.serial != serial:
                    conn.close()
                else:
                    return conn, dev.pid, info
            except Exception as e:
                logger.debug("Error connecting", exc_info=e)

    if USB_INTERFACE.FIDO in interfaces:
        for dev in list_ctap_devices():
            try:
                conn = dev.open_ctap_connection()
                info = read_info(dev.pid, conn)
                if serial and info.serial != serial:
                    conn.close()
                else:
                    return conn, dev.pid, info
            except Exception as e:
                logger.debug("Error connecting", exc_info=e)

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
    # AID.OTP: APPLICATION.OTP,  # NB: OTP will be checked elsewhere
    AID.FIDO: APPLICATION.U2F,
    AID_U2F_YUBICO: APPLICATION.U2F,
    AID.PIV: APPLICATION.PIV,
    AID.OPGP: APPLICATION.OPGP,
    AID.OATH: APPLICATION.OATH,
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
    applications = USB_INTERFACE.CCID

    # Try to read serial (and version if needed) from OTP application
    try:
        otp_version, serial = _otp_read_data(conn)
        applications |= APPLICATION.OTP
        if version is None:
            version = otp_version
    except ApplicationNotAvailableError:
        logger.debug("Unable to select OTP application")
        serial = None

    # Scan for remaining applications
    protocol = SmartCardProtocol(conn)
    for aid, code in SCAN_APPLETS.items():
        try:
            logger.debug("Check for %s", code)
            protocol.select(aid)
            applications |= code
            logger.debug("Found applet: aid: %s, capability: %s", aid, code)
        except ApplicationNotAvailableError:
            logger.debug("Missing applet: aid: %s, capability: %s", aid, code)
        except Exception as e:
            logger.error(
                "Error selecting aid: %s, capability: %s", aid, code, exc_info=e,
            )

    # Assume U2F on devices >= 3.3.0
    if USB_INTERFACE.FIDO in interfaces or version >= (3, 3, 0):
        applications |= APPLICATION.U2F

    return DeviceInfo(
        config=DeviceConfig(
            enabled_applications={
                TRANSPORT.USB: applications,
                TRANSPORT.NFC: applications,
            },
            auto_eject_timeout=0,
            challenge_response_timeout=0,
            device_flags=0,
        ),
        serial=serial,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_applications={
            TRANSPORT.USB: applications,
            TRANSPORT.NFC: applications,
        },
        is_locked=False,
    )


def _read_info_otp(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        return mgmt.read_device_info()
    except (ApplicationNotAvailableError, NotSupportedError):
        logger.debug("Unable to get info via Management application, use fallback")

    # Synthesize info
    version, serial = _otp_read_data(conn)

    if key_type == YUBIKEY.NEO:
        usb_supported = BASE_NEO_APPS
        if USB_INTERFACE.FIDO in interfaces or version >= (3, 3, 0):
            usb_supported |= APPLICATION.U2F
        applications = {
            TRANSPORT.USB: usb_supported,
            TRANSPORT.NFC: usb_supported,
        }
    elif key_type == YUBIKEY.YKP:
        applications = {
            TRANSPORT.USB: APPLICATION.OTP | TRANSPORT.U2F,
        }
    else:
        applications = {
            TRANSPORT.USB: APPLICATION.OTP,
        }

    return DeviceInfo(
        config=DeviceConfig(
            enabled_applications=applications.copy(),
            auto_eject_timeout=0,
            challenge_response_timeout=0,
            device_flags=0,
        ),
        serial=serial,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_applications=applications.copy(),
        is_locked=False,
    )


def _read_info_ctap(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        return mgmt.read_device_info()
    except Exception:  # SKY 1 or NEO
        version = (3, 0, 0)  # Guess, no way to know
        enabled_apps = {TRANSPORT.USB: APPLICATION.U2F}
        if USB_INTERFACE.CCID in interfaces:
            enabled_apps[TRANSPORT.USB] |= (
                APPLICATION.OPGP | APPLICATION.PIV | APPLICATION.OATH
            )
        if USB_INTERFACE.OTP in interfaces:
            enabled_apps[TRANSPORT.USB] |= APPLICATION.OTP

        supported_apps = {TRANSPORT.USB: APPLICATION.U2F}
        if key_type == YUBIKEY.NEO:
            supported_apps[TRANSPORT.USB] |= BASE_NEO_APPS
            supported_apps[TRANSPORT.NFC] = supported_apps[TRANSPORT.USB]
            enabled_apps[TRANSPORT.NFC] = supported_apps[TRANSPORT.NFC]

        return DeviceInfo(
            config=DeviceConfig(
                enabled_applications=enabled_apps,
                auto_eject_timeout=0,
                challenge_response_timeout=0,
                device_flags=0,
            ),
            serial=None,
            version=version,
            form_factor=FORM_FACTOR.USB_A_KEYCHAIN,
            supported_applications=supported_apps,
            is_locked=False,
        )


def read_info(pid: Optional[PID], conn: Connection) -> DeviceInfo:
    """Read out a DeviceInfo object from a YubiKey, or attempt to synthesize one."""
    if pid:
        key_type = pid.get_type()
        interfaces = pid.get_interfaces()
    else:  # No PID for NFC connections
        key_type = None
        interfaces = USB_INTERFACE(0)

    if isinstance(conn, SmartCardConnection):
        info = _read_info_ccid(conn, key_type, interfaces)
    elif isinstance(conn, OtpConnection):
        info = _read_info_otp(conn, key_type, interfaces)
    elif isinstance(conn, CtapDevice):
        info = _read_info_ctap(conn, key_type, interfaces)

    logger.debug("Read info: %s", info)

    # Set usb_enabled if missing (pre YubiKey 5)
    if (
        info.has_transport(TRANSPORT.USB)
        and TRANSPORT.USB not in info.config.enabled_applications
    ):
        usb_enabled = info.supported_applications[TRANSPORT.USB]
        if usb_enabled == (APPLICATION.OTP | APPLICATION.U2F | USB_INTERFACE.CCID):
            # YubiKey Edge, hide unusable CCID interface
            usb_enabled = APPLICATION.OTP | APPLICATION.U2F
            info.supported_applications = {TRANSPORT.USB: usb_enabled}

        if USB_INTERFACE.OTP not in interfaces:
            usb_enabled &= ~APPLICATION.OTP
        if USB_INTERFACE.FIDO not in interfaces:
            usb_enabled &= ~(APPLICATION.U2F | APPLICATION.FIDO2)
        if USB_INTERFACE.CCID not in interfaces:
            usb_enabled &= ~(
                USB_INTERFACE.CCID
                | APPLICATION.OATH
                | APPLICATION.OPGP
                | APPLICATION.PIV
            )
        info.config.enabled_applications[TRANSPORT.USB] = usb_enabled

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
        info.supported_applications = {
            TRANSPORT.USB: info.supported_applications[TRANSPORT.USB]
        }
        info.config.enabled_applications = {
            TRANSPORT.USB: info.config.enabled_applications[TRANSPORT.USB]
        }

    return info


def _fido_only(applications):
    return applications & ~(APPLICATION.U2F | APPLICATION.FIDO2) == 0


def get_name(info: DeviceInfo, key_type: Optional[YUBIKEY]) -> str:
    """Determine the product name of a YubiKey"""
    usb_supported = info.supported_applications[TRANSPORT.USB]
    if not key_type:
        if info.serial is None and _fido_only(usb_supported):
            key_type = YUBIKEY.SKY
        elif info.version[0] == 3:
            key_type = YUBIKEY.NEO
        else:
            key_type = YUBIKEY.YK4

    device_name = key_type.value

    if key_type == YUBIKEY.SKY:
        if APPLICATION.FIDO2 not in usb_supported:
            device_name = "FIDO U2F Security Key"  # SKY 1
        if info.has_transport(TRANSPORT.NFC):
            device_name = "Security Key NFC"
    elif key_type == YUBIKEY.YK4:
        if usb_supported == APPLICATION.OTP | APPLICATION.U2F:
            device_name = "YubiKey Edge"
        elif (5, 0, 0) <= info.version < (5, 1, 0) or info.version in [
            (5, 2, 0),
            (5, 2, 1),
            (5, 2, 2),
        ]:
            device_name = "YubiKey Preview"
        elif info.version >= (5, 1, 0):
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

        elif is_fips_version(info.version):
            device_name = "YubiKey FIPS"

    return device_name
