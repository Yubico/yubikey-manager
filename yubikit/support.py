# Copyright (c) 2015-2022 Yubico AB
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

import logging
from dataclasses import replace

from _yubikit_native.device import get_name as _get_name_native
from _yubikit_native.device import read_info_ccid as _read_info_ccid_native

from .core import (
    PID,
    TRANSPORT,
    YUBIKEY,
    ApplicationNotAvailableError,
    CommandError,
    Connection,
    NotSupportedError,
    Version,
)
from .core.fido import FidoConnection
from .core.otp import OtpConnection
from .core.smartcard import SmartCardConnection
from .management import (
    CAPABILITY,
    DEVICE_FLAG,
    FORM_FACTOR,
    USB_INTERFACE,
    DeviceConfig,
    DeviceInfo,
    ManagementSession,
    VersionQualifier,
    _device_info_from_native,
)
from .yubiotp import YubiOtpSession

logger = logging.getLogger(__name__)


_BASE_NEO_APPS = CAPABILITY.OTP | CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP


def _read_info_otp(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        return mgmt.read_device_info()
    except (ApplicationNotAvailableError, NotSupportedError):
        logger.debug("Unable to get info via Management application, use fallback")

    # Synthesize info
    otp = YubiOtpSession(conn)
    try:
        serial = otp.get_serial()
    except CommandError:
        logger.debug("Unable to read serial over OTP, no serial", exc_info=True)
        serial = None
    version = otp.version

    if key_type == YUBIKEY.NEO:
        usb_supported = _BASE_NEO_APPS
        if USB_INTERFACE.FIDO in interfaces or version >= (3, 3, 0):
            usb_supported |= CAPABILITY.U2F
        capabilities = {
            TRANSPORT.USB: usb_supported,
            TRANSPORT.NFC: usb_supported,
        }
    elif key_type == YUBIKEY.YKP:
        capabilities = {
            TRANSPORT.USB: CAPABILITY.OTP | CAPABILITY.U2F,
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
            device_flags=DEVICE_FLAG(0),
        ),
        serial=serial,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_capabilities=capabilities.copy(),
        is_locked=False,
        version_qualifier=VersionQualifier(version),
    )


def _read_info_ctap(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        return mgmt.read_device_info()
    except Exception:  # SKY 1, NEO, or YKP
        logger.debug("Unable to get info via Management application, use fallback")

        # Best guess version
        if key_type == YUBIKEY.YKP:
            version = Version(4, 0, 0)
        else:
            version = Version(3, 0, 0)

        supported_apps = {TRANSPORT.USB: CAPABILITY.U2F}
        if key_type == YUBIKEY.NEO:
            supported_apps[TRANSPORT.USB] |= _BASE_NEO_APPS
            supported_apps[TRANSPORT.NFC] = supported_apps[TRANSPORT.USB]

        return DeviceInfo(
            config=DeviceConfig(
                enabled_capabilities={},  # Populated later
                auto_eject_timeout=0,
                challenge_response_timeout=0,
                device_flags=DEVICE_FLAG(0),
            ),
            serial=None,
            version=version,
            form_factor=FORM_FACTOR.USB_A_KEYCHAIN,
            supported_capabilities=supported_apps,
            is_locked=False,
            version_qualifier=VersionQualifier(version),
        )


def read_info(conn: Connection, pid: PID | None = None) -> DeviceInfo:
    """Reads out DeviceInfo from a YubiKey, or attempts to synthesize the data.

    Reading DeviceInfo from a ManagementSession is only supported for newer YubiKeys.
    This function attempts to read that information, but will fall back to gathering the
    data using other mechanisms if needed. It will also make adjustments to the data if
    required, for example to "fix" known bad values.

    The *pid* parameter must be provided whenever the YubiKey is connected via USB.

    :param conn: A connection to a YubiKey.
    :param pid: The USB Product ID.
    """

    logger.debug(f"Attempting to read device info, using {type(conn).__name__}")

    if isinstance(conn, SmartCardConnection):
        # CCID path fully handled by native Rust implementation
        d = _read_info_ccid_native(conn)
        return _device_info_from_native(d)

    # For OTP/FIDO, keep existing Python paths
    if pid:
        key_type: YUBIKEY | None = pid.yubikey_type
        interfaces = pid.usb_interfaces
    else:
        raise ValueError("PID must be provided for non-NFC connections")

    if isinstance(conn, OtpConnection):
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
            # YubiKey Edge, hide unusable CCID interface from supported
            info.supported_capabilities = {
                TRANSPORT.USB: CAPABILITY.OTP | CAPABILITY.U2F
            }

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

    # SKY identified by PID
    if key_type == YUBIKEY.SKY:
        info.is_sky = True

    # YK4-based FIPS version
    if (4, 4, 0) <= info.version < (4, 5, 0):
        info.is_fips = True

    # Fix NFC if needed
    if info.has_transport(TRANSPORT.NFC):
        # Set nfc_enabled if missing (pre YubiKey 5)
        if TRANSPORT.NFC not in info.config.enabled_capabilities:
            info.config.enabled_capabilities[TRANSPORT.NFC] = (
                info.supported_capabilities[TRANSPORT.NFC]
            )
        # Workaround for invalid configurations
        if info.form_factor in (
            FORM_FACTOR.USB_A_NANO,
            FORM_FACTOR.USB_C_NANO,
            FORM_FACTOR.USB_C_LIGHTNING,
        ) or (
            info.form_factor is FORM_FACTOR.USB_C_KEYCHAIN and info.version < (5, 2, 4)
        ):
            # Known to not have NFC, remove capabilities
            supported = dict(info.supported_capabilities)
            del supported[TRANSPORT.NFC]
            replace(info, supported_capabilities=supported)
            del info.config.enabled_capabilities[TRANSPORT.NFC]

    logger.debug("Device info, after tweaks: %s", info)
    return info


def get_name(info: DeviceInfo, key_type: YUBIKEY | None) -> str:
    """Determine the product name of a YubiKey

    :param info: The device info.
    :param key_type: The YubiKey hardware platform.
    """
    return _get_name_native(
        version=(info.version[0], info.version[1], info.version[2]),
        form_factor=int(info.form_factor),
        is_sky=info.is_sky,
        is_fips=info.is_fips,
        pin_complexity=info.pin_complexity,
        serial=info.serial,
        usb_supported=int(
            info.supported_capabilities.get(TRANSPORT.USB, CAPABILITY(0))
        ),
        has_nfc=info.has_transport(TRANSPORT.NFC),
    )
