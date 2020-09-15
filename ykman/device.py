# Copyright (c) 2015 Yubico AB
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

from __future__ import absolute_import

from yubikit.core import AID, INTERFACE, TRANSPORT, APPLICATION, FORM_FACTOR, YUBIKEY
from yubikit.core.otp import OtpConnection
from yubikit.core.iso7816 import Iso7816Connection, Iso7816Application, ApduError
from yubikit.mgmt import ManagementApplication, DeviceInfo, DeviceConfig
from yubikit.otp import YkCfgApplication
from fido2.ctap import CtapDevice
from .hid import list_otp_devices, list_ctap_devices
from .scard import list_devices as list_ccid_devices

from collections import Counter
import logging

logger = logging.getLogger(__name__)


def is_fips_version(version):
    return (4, 4, 0) <= version < (4, 5, 0)


AID_U2F_YUBICO = b"\xa0\x00\x00\x05\x27\x10\x02"  # Old U2F AID

NEO_APPLETS = {
    AID.OTP: APPLICATION.OTP,
    AID.FIDO: APPLICATION.U2F,
    AID_U2F_YUBICO: APPLICATION.U2F,
    AID.PIV: APPLICATION.PIV,
    AID.OPGP: APPLICATION.OPGP,
    AID.OATH: APPLICATION.OATH,
}


BASE_NEO_APPS = APPLICATION.OTP | APPLICATION.OATH | APPLICATION.PIV | APPLICATION.OPGP


def scan_devices():
    """Scan for attached YubiKeys, without opening any connections.

    Returns a dict mapping PID to device count, and a state object which can be used to
    detect changes in attached devices.
    """
    # Scans all attached devices, without opening any connections.
    merged = {}
    otp_devs = list_otp_devices()
    ctap_devs = list_ctap_devices()
    ccid_devs = list_ccid_devices()
    merged.update(Counter(d.pid for d in otp_devs))
    merged.update(Counter(d.pid for d in ctap_devs))
    merged.update(Counter(d.pid for d in ccid_devs))
    state = {d.fingerprint for d in otp_devs + ctap_devs + ccid_devs}
    return merged, state


def list_all_devices():
    """Connects to all attached YubiKeys and reads device info from them.

    Returns a list of (PID, info) tuples for each connected device."""
    # List all attached devices, returning pid and info for each.
    handled_pids = set()
    otp_devs = list_otp_devices()
    ctap_devs = list_ctap_devices()
    ccid_devs = list_ccid_devices()
    pids = {}
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
    for dev in otp_devs:
        handle(dev, dev.open_otp_connection)
    handled_pids.update({pid for pid, handled in pids.items() if handled})

    # Handle CCID devices
    for dev in ccid_devs:
        handle(dev, dev.open_iso7816_connection)
    handled_pids.update({pid for pid, handled in pids.items() if handled})

    # Handle FIDO devices
    for dev in ctap_devs:
        handle(dev, dev.open_ctap_connection)
    handled_pids.update({pid for pid, handled in pids.items() if handled})

    return devices


def connect_to_device(serial=None, transports=sum(TRANSPORT)):
    """Get a connection to a YubiKey using one of the provided transports.

    Returns a tuple of (connection, pid, info) for the device.
    """
    if TRANSPORT.has(transports, TRANSPORT.CCID):
        for dev in list_ccid_devices():
            conn = dev.open_iso7816_connection()
            info = read_info(dev.pid, conn)
            if serial and info.serial != serial:
                conn.close()
            else:
                return conn, dev.pid, info
    if TRANSPORT.has(transports, TRANSPORT.OTP):
        for dev in list_otp_devices():
            conn = dev.open_otp_connection()
            info = read_info(dev.pid, conn)
            if serial and info.serial != serial:
                conn.close()
            else:
                return conn, dev.pid, info
    if TRANSPORT.has(transports, TRANSPORT.FIDO):
        for dev in list_ctap_devices():
            conn = dev.open_ctap_connection()
            info = read_info(dev.pid, conn)
            if serial and info.serial != serial:
                conn.close()
            else:
                return conn, dev.pid, info
    if serial:
        raise ValueError("YubiKey with given serial not found")
    raise ValueError("No YubiKey found for the given transports")


def probe_applications(conn):
    capa = TRANSPORT.CCID
    for aid, code in NEO_APPLETS.items():
        try:
            Iso7816Application(aid, conn)
            capa |= code
            logger.debug("Found applet: aid: %s , capability: %s", aid, code)
        except ApduError:
            logger.debug("Missing applet: aid: %s , capability: %s", aid, code)
    return capa


def read_info(pid, conn):
    if pid:
        key_type = pid.get_type()
        transports = pid.get_transports()
    else:
        key_type = None
        transports = 0

    # Get for CCID
    if isinstance(conn, Iso7816Connection):
        try:
            mgmt = ManagementApplication(conn)
            version = mgmt.version
            info = mgmt.read_device_info()
        except Exception:
            if key_type == YUBIKEY.NEO:
                try:
                    # Workaround to "de-select" the Management Applet
                    conn.transceive(b"\xa4\x04\x00\x08")
                    ykcfg = YkCfgApplication(conn)
                    serial = ykcfg.get_serial()
                except Exception as e:
                    logger.debug("Unable to read serial via OtpApplication", exc_info=e)
                    serial = None
                applications = probe_applications(conn)
                if TRANSPORT.has(transports, TRANSPORT.FIDO) or version >= (3, 3, 0):
                    applications |= APPLICATION.U2F

                info = DeviceInfo(
                    config=DeviceConfig(
                        enabled_applications={
                            INTERFACE.USB: applications,
                            INTERFACE.NFC: applications,
                        },
                        auto_eject_timeout=0,
                        challenge_response_timeout=0,
                        device_flags=0,
                    ),
                    serial=serial,
                    version=version,
                    form_factor=FORM_FACTOR.UNKNOWN,
                    supported_applications={
                        INTERFACE.USB: applications,
                        INTERFACE.NFC: applications,
                    },
                    is_locked=False,
                )
            else:
                raise ValueError("Unhandled key")

    # Get for OTP
    elif isinstance(conn, OtpConnection):
        try:
            mgmt = ManagementApplication(conn)
            info = mgmt.read_device_info()
        except Exception:
            ykcfg = YkCfgApplication(conn)
            version = ykcfg.version
            try:
                serial = ykcfg.get_serial()
            except Exception:
                serial = None

            if key_type == YUBIKEY.NEO:
                usb_supported = BASE_NEO_APPS
                if TRANSPORT.has(transports, TRANSPORT.FIDO) or version >= (3, 3, 0):
                    usb_supported |= APPLICATION.U2F
                applications = {
                    INTERFACE.USB: usb_supported,
                    INTERFACE.NFC: usb_supported,
                }
            elif key_type == YUBIKEY.YKP:
                applications = {
                    INTERFACE.USB: APPLICATION.OTP | INTERFACE.U2F,
                }
            else:
                applications = {
                    INTERFACE.USB: APPLICATION.OTP,
                }

            info = DeviceInfo(
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

    # Get for CTAP
    elif isinstance(conn, CtapDevice):
        try:
            mgmt = ManagementApplication(conn)
            info = mgmt.read_device_info()
        except Exception:  # SKY 1 or NEO
            version = (3, 0, 0)  # Guess, no way to know
            enabled_apps = {INTERFACE.USB: APPLICATION.U2F}
            if TRANSPORT.has(transports, TRANSPORT.CCID):
                enabled_apps[INTERFACE.USB] |= (
                    APPLICATION.OPGP | APPLICATION.PIV | APPLICATION.OATH
                )
            if TRANSPORT.has(transports, TRANSPORT.OTP):
                enabled_apps[INTERFACE.USB] |= APPLICATION.OTP

            supported_apps = {INTERFACE.USB: APPLICATION.U2F}
            if key_type == YUBIKEY.NEO:
                supported_apps[INTERFACE.USB] |= BASE_NEO_APPS
                supported_apps[INTERFACE.NFC] = supported_apps[INTERFACE.USB]
                enabled_apps[INTERFACE.NFC] = supported_apps[INTERFACE.NFC]

            info = DeviceInfo(
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

    # Set usb_enabled for pre YubiKey 5
    if info.version < (5, 0, 0):
        if info.version == (4, 2, 4):  # Doesn't report correctly
            info = info._replace(supported_applications={INTERFACE.USB: 0x3F})

        usb_enabled = info.supported_applications[INTERFACE.USB]
        if usb_enabled == (APPLICATION.OTP | APPLICATION.U2F | TRANSPORT.CCID):
            # YubiKey Edge, hide unusable CCID interface
            usb_enabled = APPLICATION.OTP | APPLICATION.U2F
            info = info._replace(supported_applications={INTERFACE.USB: usb_enabled},)

        if not TRANSPORT.has(transports, TRANSPORT.OTP):
            usb_enabled &= ~APPLICATION.OTP
        if not TRANSPORT.has(transports, TRANSPORT.FIDO):
            usb_enabled &= ~(APPLICATION.U2F | APPLICATION.FIDO2)
        if not TRANSPORT.has(transports, TRANSPORT.CCID):
            usb_enabled &= ~(
                TRANSPORT.CCID | APPLICATION.OATH | APPLICATION.OPGP | APPLICATION.PIV
            )
        info.config.enabled_applications[INTERFACE.USB] = usb_enabled

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
        info = info._replace(
            supported_applications={
                INTERFACE.USB: info.supported_applications[INTERFACE.USB]
            },
            config=info.config._replace(
                enabled_applications={
                    INTERFACE.USB: info.config.enabled_applications[INTERFACE.USB]
                }
            ),
        )

    return info


def get_name(key_type, info):
    device_name = key_type.value
    usb_supported = info.supported_applications.get(INTERFACE.USB)

    if key_type == YUBIKEY.SKY:
        if not APPLICATION.has(usb_supported, APPLICATION.FIDO2):
            device_name = "FIDO U2F Security Key"  # SKY 1
        if INTERFACE.NFC in info.supported_applications:
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
            if (
                info.form_factor == FORM_FACTOR.USB_A_KEYCHAIN
                and INTERFACE.NFC not in info.supported_applications
            ):
                device_name += "A"
            elif info.form_factor == FORM_FACTOR.USB_A_KEYCHAIN:
                device_name += " NFC"
            elif info.form_factor == FORM_FACTOR.USB_A_NANO:
                device_name += " Nano"
            elif info.form_factor == FORM_FACTOR.USB_C_KEYCHAIN:
                device_name += "C"
                if INTERFACE.NFC in info.supported_applications:
                    device_name += " NFC"
            elif info.form_factor == FORM_FACTOR.USB_C_NANO:
                device_name += "C Nano"
            elif info.form_factor == FORM_FACTOR.USB_C_LIGHTNING:
                device_name += "Ci"

        elif is_fips_version(info.version):
            device_name = "YubiKey FIPS"

    return device_name


YubiKey = None
