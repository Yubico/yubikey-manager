# Copyright (c) 2020 Yubico AB
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

from .core import (
    bytes2int,
    int2bytes,
    require_version,
    Version,
    Tlv,
    TRANSPORT,
    USB_INTERFACE,
    NotSupportedError,
    BadResponseError,
    ApplicationNotAvailableError,
)
from .core.otp import (
    check_crc,
    OtpConnection,
    OtpProtocol,
    STATUS_OFFSET_PROG_SEQ,
    CommandRejectedError,
)
from .core.fido import FidoConnection
from .core.smartcard import AID, SmartCardConnection, SmartCardProtocol, ScpKeyParams
from fido2.hid import CAPABILITY as CTAP_CAPABILITY

from enum import IntEnum, IntFlag, unique
from dataclasses import dataclass, field
from typing import Optional, Union, Mapping
import abc
import struct
import warnings
import logging

logger = logging.getLogger(__name__)


@unique
class CAPABILITY(IntFlag):
    """YubiKey Application identifiers."""

    OTP = 0x01
    U2F = 0x02
    FIDO2 = 0x200
    OATH = 0x20
    PIV = 0x10
    OPENPGP = 0x08
    HSMAUTH = 0x100

    def __str__(self):
        name = "|".join(c.name or str(c) for c in CAPABILITY if c in self)
        return f"{name}: {hex(self)}"

    @classmethod
    def _from_fips(cls, fips: int) -> "CAPABILITY":
        c = CAPABILITY(0)
        if fips & (1 << 0):
            c |= CAPABILITY.FIDO2
        if fips & (1 << 1):
            c |= CAPABILITY.PIV
        if fips & (1 << 2):
            c |= CAPABILITY.OPENPGP
        if fips & (1 << 3):
            c |= CAPABILITY.OATH
        if fips & (1 << 4):
            c |= CAPABILITY.HSMAUTH
        return c

    @classmethod
    def _from_aid(cls, aid: AID) -> "CAPABILITY":
        # TODO: match on prefix?
        try:
            return getattr(CAPABILITY, aid.name)
        except AttributeError:
            pass
        if aid == AID.FIDO:
            return CAPABILITY.FIDO2
        raise ValueError("Unhandled AID")

    @property
    def display_name(self) -> str:
        if self == 0:
            return "None"
        if bin(self).count("1") > 1:
            i = 1
            names = []
            while i < self:
                if i & self:
                    names.append(CAPABILITY(i).display_name)
                i <<= 1
            return ", ".join(names)

        if self == CAPABILITY.OTP:
            return "Yubico OTP"
        elif self == CAPABILITY.U2F:
            return "FIDO U2F"
        elif self == CAPABILITY.OPENPGP:
            return "OpenPGP"
        elif self == CAPABILITY.HSMAUTH:
            return "YubiHSM Auth"
        return self.name or f"Unknown(0x{self:x})"

    @property
    def usb_interfaces(self) -> USB_INTERFACE:
        ifaces = USB_INTERFACE(0)
        if self & CAPABILITY.OTP:
            ifaces |= USB_INTERFACE.OTP
        if self & (CAPABILITY.U2F | CAPABILITY.FIDO2):
            ifaces |= USB_INTERFACE.FIDO
        if self & (
            0x4  # General CCID bit
            | 0x400  # Management over CCID bit
            | CAPABILITY.OATH
            | CAPABILITY.PIV
            | CAPABILITY.OPENPGP
            | CAPABILITY.HSMAUTH
        ):
            ifaces |= USB_INTERFACE.CCID
        return ifaces


@unique
class FORM_FACTOR(IntEnum):
    """YubiKey device form factors."""

    UNKNOWN = 0x00
    USB_A_KEYCHAIN = 0x01
    USB_A_NANO = 0x02
    USB_C_KEYCHAIN = 0x03
    USB_C_NANO = 0x04
    USB_C_LIGHTNING = 0x05
    USB_A_BIO = 0x06
    USB_C_BIO = 0x07

    def __str__(self):
        if self == FORM_FACTOR.USB_A_KEYCHAIN:
            return "Keychain (USB-A)"
        elif self == FORM_FACTOR.USB_A_NANO:
            return "Nano (USB-A)"
        elif self == FORM_FACTOR.USB_C_KEYCHAIN:
            return "Keychain (USB-C)"
        elif self == FORM_FACTOR.USB_C_NANO:
            return "Nano (USB-C)"
        elif self == FORM_FACTOR.USB_C_LIGHTNING:
            return "Keychain (USB-C, Lightning)"
        elif self == FORM_FACTOR.USB_A_BIO:
            return "Bio (USB-A)"
        elif self == FORM_FACTOR.USB_C_BIO:
            return "Bio (USB-C)"
        else:
            return "Unknown"

    @classmethod
    def from_code(cls, code: int) -> "FORM_FACTOR":
        if code and not isinstance(code, int):
            raise ValueError(f"Invalid form factor code: {code}")
        code &= 0xF
        return cls(code) if code in cls.__members__.values() else cls.UNKNOWN


@unique
class DEVICE_FLAG(IntFlag):
    """Configuration flags."""

    REMOTE_WAKEUP = 0x40
    EJECT = 0x80


TAG_USB_SUPPORTED = 0x01
TAG_SERIAL = 0x02
TAG_USB_ENABLED = 0x03
TAG_FORM_FACTOR = 0x04
TAG_VERSION = 0x05
TAG_AUTO_EJECT_TIMEOUT = 0x06
TAG_CHALRESP_TIMEOUT = 0x07
TAG_DEVICE_FLAGS = 0x08
TAG_APP_VERSIONS = 0x09
TAG_CONFIG_LOCK = 0x0A
TAG_UNLOCK = 0x0B
TAG_REBOOT = 0x0C
TAG_NFC_SUPPORTED = 0x0D
TAG_NFC_ENABLED = 0x0E
TAG_IAP_DETECTION = 0x0F
TAG_MORE_DATA = 0x10
TAG_FREE_FORM = 0x11
TAG_HID_INIT_DELAY = 0x12
TAG_PART_NUMBER = 0x13
TAG_FIPS_CAPABLE = 0x14
TAG_FIPS_APPROVED = 0x15
TAG_PIN_COMPLEXITY = 0x16
TAG_NFC_RESTRICTED = 0x17
TAG_RESET_BLOCKED = 0x18
TAG_FPS_VERSION = 0x20
TAG_STM_VERSION = 0x21


@dataclass
class DeviceConfig:
    """Management settings for YubiKey which can be configured by the user."""

    enabled_capabilities: Mapping[TRANSPORT, CAPABILITY] = field(default_factory=dict)
    auto_eject_timeout: Optional[int] = None
    challenge_response_timeout: Optional[int] = None
    device_flags: Optional[DEVICE_FLAG] = None
    nfc_restricted: Optional[bool] = None

    def get_bytes(
        self,
        reboot: bool,
        cur_lock_code: Optional[bytes] = None,
        new_lock_code: Optional[bytes] = None,
    ) -> bytes:
        buf = b""
        if reboot:
            buf += Tlv(TAG_REBOOT)
        if cur_lock_code:
            buf += Tlv(TAG_UNLOCK, cur_lock_code)
        usb_enabled = self.enabled_capabilities.get(TRANSPORT.USB)
        if usb_enabled is not None:
            buf += Tlv(TAG_USB_ENABLED, int2bytes(usb_enabled, 2))
        nfc_enabled = self.enabled_capabilities.get(TRANSPORT.NFC)
        if nfc_enabled is not None:
            buf += Tlv(TAG_NFC_ENABLED, int2bytes(nfc_enabled, 2))
        if self.auto_eject_timeout is not None:
            buf += Tlv(TAG_AUTO_EJECT_TIMEOUT, int2bytes(self.auto_eject_timeout, 2))
        if self.challenge_response_timeout is not None:
            buf += Tlv(TAG_CHALRESP_TIMEOUT, int2bytes(self.challenge_response_timeout))
        if self.device_flags is not None:
            buf += Tlv(TAG_DEVICE_FLAGS, int2bytes(self.device_flags))
        if new_lock_code:
            buf += Tlv(TAG_CONFIG_LOCK, new_lock_code)
        if self.nfc_restricted:
            buf += Tlv(TAG_NFC_RESTRICTED, b"\1")
        if len(buf) > 0xFF:
            raise NotSupportedError("DeviceConfiguration too large")
        return int2bytes(len(buf)) + buf


@dataclass
class DeviceInfo:
    """Information about a YubiKey readable using the ManagementSession."""

    config: DeviceConfig
    serial: Optional[int]
    version: Version
    form_factor: FORM_FACTOR
    supported_capabilities: Mapping[TRANSPORT, CAPABILITY]
    is_locked: bool
    is_fips: bool = False
    is_sky: bool = False
    part_number: Optional[str] = None
    fips_capable: CAPABILITY = CAPABILITY(0)
    fips_approved: CAPABILITY = CAPABILITY(0)
    pin_complexity: bool = False
    reset_blocked: CAPABILITY = CAPABILITY(0)
    fps_version: Optional[Version] = None
    stm_version: Optional[Version] = None

    @property
    def _is_bio(self) -> bool:
        return self.form_factor in (FORM_FACTOR.USB_A_BIO, FORM_FACTOR.USB_C_BIO)

    def has_transport(self, transport: TRANSPORT) -> bool:
        return transport in self.supported_capabilities

    @classmethod
    def parse(cls, encoded: bytes, default_version: Version) -> "DeviceInfo":
        if len(encoded) - 1 != encoded[0]:
            raise BadResponseError("Invalid length")
        return cls.parse_tlvs(Tlv.parse_dict(encoded[1:]), default_version)

    @classmethod
    def parse_tlvs(
        cls, data: Mapping[int, bytes], default_version: Version
    ) -> "DeviceInfo":
        locked = data.get(TAG_CONFIG_LOCK) == b"\1"
        serial = bytes2int(data.get(TAG_SERIAL, b"\0")) or None
        ff_value = bytes2int(data.get(TAG_FORM_FACTOR, b"\0"))
        form_factor = FORM_FACTOR.from_code(ff_value)
        fips = bool(ff_value & 0x80)
        sky = bool(ff_value & 0x40)
        if TAG_VERSION in data:
            version = Version.from_bytes(data[TAG_VERSION])
        else:
            version = default_version
        auto_eject_to = bytes2int(data.get(TAG_AUTO_EJECT_TIMEOUT, b"\0"))
        chal_resp_to = bytes2int(data.get(TAG_CHALRESP_TIMEOUT, b"\0"))
        flags = DEVICE_FLAG(bytes2int(data.get(TAG_DEVICE_FLAGS, b"\0")))

        supported = {}
        enabled = {}

        if version == (4, 2, 4):  # Doesn't report correctly
            supported[TRANSPORT.USB] = CAPABILITY(0x3F)
        else:
            supported[TRANSPORT.USB] = CAPABILITY(bytes2int(data[TAG_USB_SUPPORTED]))
        if TAG_USB_ENABLED in data:  # From YK 5.0.0
            if not ((4, 0, 0) <= version < (5, 0, 0)):  # Broken on YK4
                enabled[TRANSPORT.USB] = CAPABILITY(bytes2int(data[TAG_USB_ENABLED]))
        if TAG_NFC_SUPPORTED in data:  # YK with NFC
            supported[TRANSPORT.NFC] = CAPABILITY(bytes2int(data[TAG_NFC_SUPPORTED]))
            enabled[TRANSPORT.NFC] = CAPABILITY(bytes2int(data[TAG_NFC_ENABLED]))
        nfc_restricted = data.get(TAG_NFC_RESTRICTED, b"\0") == b"\1"
        try:
            part_number = data.get(TAG_PART_NUMBER, b"").decode() or None
        except UnicodeDecodeError:
            part_number = None
        fips_capable = CAPABILITY._from_fips(
            bytes2int(data.get(TAG_FIPS_CAPABLE, b"\0"))
        )
        fips_approved = CAPABILITY._from_fips(
            bytes2int(data.get(TAG_FIPS_APPROVED, b"\0"))
        )
        pin_complexity = data.get(TAG_PIN_COMPLEXITY, b"\0") == b"\1"
        reset_blocked = CAPABILITY(bytes2int(data.get(TAG_RESET_BLOCKED, b"\0")))
        fps_version = Version.from_bytes(data.get(TAG_FPS_VERSION, b"\0\0\0"))
        stm_version = Version.from_bytes(data.get(TAG_STM_VERSION, b"\0\0\0"))

        return cls(
            DeviceConfig(enabled, auto_eject_to, chal_resp_to, flags, nfc_restricted),
            serial,
            version,
            form_factor,
            supported,
            locked,
            fips,
            sky,
            part_number,
            fips_capable,
            fips_approved,
            pin_complexity,
            reset_blocked,
            fps_version or None,
            stm_version or None,
        )


_MODES = [
    USB_INTERFACE.OTP,  # 0x00
    USB_INTERFACE.CCID,  # 0x01
    USB_INTERFACE.OTP | USB_INTERFACE.CCID,  # 0x02
    USB_INTERFACE.FIDO,  # 0x03
    USB_INTERFACE.OTP | USB_INTERFACE.FIDO,  # 0x04
    USB_INTERFACE.FIDO | USB_INTERFACE.CCID,  # 0x05
    USB_INTERFACE.OTP | USB_INTERFACE.FIDO | USB_INTERFACE.CCID,  # 0x06
]


@dataclass(init=False, repr=False)
class Mode:
    """YubiKey USB Mode configuration for use with YubiKey NEO and 4."""

    code: int
    interfaces: USB_INTERFACE

    def __init__(self, interfaces: USB_INTERFACE):
        try:
            self.code = _MODES.index(interfaces)
            self.interfaces = USB_INTERFACE(interfaces)
        except ValueError:
            raise ValueError("Invalid mode!")

    def __repr__(self):
        return "+".join(t.name or str(t) for t in USB_INTERFACE if t in self.interfaces)

    @classmethod
    def from_code(cls, code: int) -> "Mode":
        # Mode is determined from the lowest 3 bits
        try:
            return cls(_MODES[code & 0b00000111])
        except IndexError:
            raise ValueError("Invalid mode code")


SLOT_DEVICE_CONFIG = 0x11
SLOT_YK4_CAPABILITIES = 0x13
SLOT_YK4_SET_DEVICE_INFO = 0x15


class _Backend(abc.ABC):
    version: Version

    @abc.abstractmethod
    def close(self) -> None: ...

    @abc.abstractmethod
    def set_mode(self, data: bytes) -> None: ...

    @abc.abstractmethod
    def read_config(self, page: int = 0) -> bytes: ...

    @abc.abstractmethod
    def write_config(self, config: bytes) -> None: ...


class _ManagementOtpBackend(_Backend):
    def __init__(self, otp_connection):
        self.protocol = OtpProtocol(otp_connection)
        self.version = self.protocol.version
        if (1, 0, 0) <= self.version < (3, 0, 0):
            raise ApplicationNotAvailableError()

    def close(self):
        self.protocol.close()

    def set_mode(self, data):
        empty = self.protocol.read_status()[STATUS_OFFSET_PROG_SEQ] == 0
        try:
            self.protocol.send_and_receive(SLOT_DEVICE_CONFIG, data)
        except CommandRejectedError:
            if empty:
                return  # ProgSeq isn't updated by set mode when empty
            raise

    def read_config(self, page: int = 0):
        response = self.protocol.send_and_receive(
            SLOT_YK4_CAPABILITIES, int2bytes(page)
        )
        r_len = response[0]
        if check_crc(response[: r_len + 1 + 2]):
            return response[: r_len + 1]
        raise BadResponseError("Invalid checksum")

    def write_config(self, config):
        self.protocol.send_and_receive(SLOT_YK4_SET_DEVICE_INFO, config)


INS_SET_MODE = 0x16
INS_READ_CONFIG = 0x1D
INS_WRITE_CONFIG = 0x1C
INS_DEVICE_RESET = 0x1F
P1_DEVICE_CONFIG = 0x11


class _ManagementSmartCardBackend(_Backend):
    def __init__(self, smartcard_connection, scp_key_params):
        self.protocol = SmartCardProtocol(smartcard_connection)
        try:
            select_bytes = self.protocol.select(AID.MANAGEMENT)

            if scp_key_params:
                self.protocol.init_scp(scp_key_params)
            elif select_bytes[-2:] == b"\x90\x00":
                # YubiKey Edge incorrectly appends SW twice.
                select_bytes = select_bytes[:-2]

            select_str = select_bytes.decode()
            self.version = Version.from_string(select_str)
            # For YubiKey NEO, we use the OTP application for further commands
            if self.version[0] == 3:
                # Workaround to "de-select" on NEO, otherwise it gets stuck.
                smartcard_connection.send_and_receive(b"\xa4\x04\x00\x08")
                self.protocol.select(AID.OTP)
        except ApplicationNotAvailableError:
            if smartcard_connection.transport == TRANSPORT.NFC:
                # Probably NEO over NFC
                status = self.protocol.select(AID.OTP)
                self.version = Version.from_bytes(status[:3])
            else:
                raise
        self.protocol.configure(self.version)

    def close(self):
        self.protocol.close()

    def set_mode(self, data):
        if self.version[0] == 3:  # Using the OTP application
            self.protocol.send_apdu(0, 0x01, SLOT_DEVICE_CONFIG, 0, data)
        else:
            self.protocol.send_apdu(0, INS_SET_MODE, P1_DEVICE_CONFIG, 0, data)

    def read_config(self, page: int = 0):
        return self.protocol.send_apdu(0, INS_READ_CONFIG, page, 0)

    def write_config(self, config):
        self.protocol.send_apdu(0, INS_WRITE_CONFIG, 0, 0, config)

    def device_reset(self):
        self.protocol.send_apdu(0, INS_DEVICE_RESET, 0, 0)


CTAP_VENDOR_FIRST = 0x40
CTAP_YUBIKEY_DEVICE_CONFIG = CTAP_VENDOR_FIRST
CTAP_READ_CONFIG = CTAP_VENDOR_FIRST + 2
CTAP_WRITE_CONFIG = CTAP_VENDOR_FIRST + 3


class _ManagementCtapBackend(_Backend):
    def __init__(self, fido_connection):
        self.ctap = fido_connection
        version = fido_connection.device_version
        if version[0] < 4:  # Prior to YK4 this was not firmware version
            if not (
                version[0] == 0 and fido_connection.capabilities & CTAP_CAPABILITY.CBOR
            ):
                version = (3, 0, 0)  # Guess that it's a NEO
        self.version = Version(*version)

    def close(self):
        self.ctap.close()

    def set_mode(self, data):
        self.ctap.call(CTAP_YUBIKEY_DEVICE_CONFIG, data)

    def read_config(self, page: int = 0):
        return self.ctap.call(CTAP_READ_CONFIG, int2bytes(page))

    def write_config(self, config):
        self.ctap.call(CTAP_WRITE_CONFIG, config)


class ManagementSession:
    def __init__(
        self,
        connection: Union[OtpConnection, SmartCardConnection, FidoConnection],
        scp_key_params: Optional[ScpKeyParams] = None,
    ):
        if isinstance(connection, OtpConnection):
            if scp_key_params:
                raise ValueError("SCP can only be used with SmartCardConnection")
            self.backend: _Backend = _ManagementOtpBackend(connection)
        elif isinstance(connection, SmartCardConnection):
            self.backend = _ManagementSmartCardBackend(connection, scp_key_params)
        elif isinstance(connection, FidoConnection):
            if scp_key_params:
                raise ValueError("SCP can only be used with SmartCardConnection")
            self.backend = _ManagementCtapBackend(connection)
        else:
            raise TypeError("Unsupported connection type")
        logger.debug(
            "Management session initialized for "
            f"connection={type(connection).__name__}, version={self.version}"
        )

    def close(self) -> None:
        """Close the underlying connection.

        :deprecated: call .close() on the underlying connection instead.
        """
        warnings.warn(
            "Deprecated: call .close() on the underlying connection instead.",
            DeprecationWarning,
        )
        self.backend.close()

    @property
    def version(self) -> Version:
        """The firmware version of the YubiKey"""
        return self.backend.version

    def read_device_info(self) -> DeviceInfo:
        """Get detailed information about the YubiKey."""
        require_version(self.version, (4, 1, 0))
        more_data = True
        tlvs = {}
        page = 0
        while more_data:
            logger.debug(f"Reading DeviceInfo page: {page}")
            encoded = self.backend.read_config(page)
            if len(encoded) - 1 != encoded[0]:
                raise BadResponseError("Invalid length")
            data = Tlv.parse_dict(encoded[1:])
            more_data = data.pop(TAG_MORE_DATA, 0) == b"\1"
            tlvs.update(data)
            page += 1

        return DeviceInfo.parse_tlvs(tlvs, self.version)

    def write_device_config(
        self,
        config: Optional[DeviceConfig] = None,
        reboot: bool = False,
        cur_lock_code: Optional[bytes] = None,
        new_lock_code: Optional[bytes] = None,
    ) -> None:
        """Write configuration settings for YubiKey.

        :param config: The device configuration.
        :param reboot: If True the YubiKey will reboot.
        :param cur_lock_code: Current lock code.
        :param new_lock_code: New lock code.
        """
        require_version(self.version, (5, 0, 0))
        if cur_lock_code is not None and len(cur_lock_code) != 16:
            raise ValueError("Lock code must be 16 bytes")
        if new_lock_code is not None and len(new_lock_code) != 16:
            raise ValueError("Lock code must be 16 bytes")
        config = config or DeviceConfig()
        logger.debug(
            f"Writing device config: {config}, reboot: {reboot}, "
            f"current lock code: {cur_lock_code is not None}, "
            f"new lock code: {new_lock_code is not None}"
        )
        self.backend.write_config(
            config.get_bytes(reboot, cur_lock_code, new_lock_code)
        )
        logger.info("Device config written")

    def set_mode(
        self,
        mode: Mode,
        chalresp_timeout: int = 0,
        auto_eject_timeout: Optional[int] = None,
    ) -> None:
        """Write connection modes (USB interfaces) for YubiKey.

        :param mode: The connection modes (USB interfaces).
        :param chalresp_timeout: The timeout when waiting for touch
            for challenge response.
        :param auto_eject_timeout: When set, the smartcard will
            automatically eject after the given time.
        """
        logger.debug(
            f"Set mode: {mode}, chalresp_timeout: {chalresp_timeout}, "
            f"auto_eject_timeout: {auto_eject_timeout}"
        )
        if self.version >= (5, 0, 0):
            # Translate into DeviceConfig
            usb_enabled = CAPABILITY(0)
            if USB_INTERFACE.OTP in mode.interfaces:
                usb_enabled |= CAPABILITY.OTP
            if USB_INTERFACE.CCID in mode.interfaces:
                usb_enabled |= (
                    CAPABILITY.OATH
                    | CAPABILITY.PIV
                    | CAPABILITY.OPENPGP
                    | CAPABILITY.HSMAUTH
                    | 0x400  # Management over CCID bit
                )
            if USB_INTERFACE.FIDO in mode.interfaces:
                usb_enabled |= CAPABILITY.U2F | CAPABILITY.FIDO2

            # Overlay with supported capabilities
            supported = self.read_device_info().supported_capabilities.get(
                TRANSPORT.USB, 0
            )
            usb_enabled = usb_enabled & supported
            logger.debug(f"Delegating to DeviceConfig with usb_enabled: {usb_enabled}")
            # N.B: reboot=False, since we're using the older set_mode command
            self.write_device_config(
                DeviceConfig(
                    {TRANSPORT.USB: usb_enabled},
                    auto_eject_timeout,
                    chalresp_timeout,
                )
            )
        else:
            code = mode.code
            if auto_eject_timeout is not None:
                if mode.interfaces == USB_INTERFACE.CCID:
                    code |= DEVICE_FLAG.EJECT
                else:
                    raise ValueError("Touch-eject only applicable for mode: CCID")
            self.backend.set_mode(
                # N.B. This is little endian!
                struct.pack("<BBH", code, chalresp_timeout, auto_eject_timeout or 0)
            )
            logger.info("Mode configuration written")

    def device_reset(self) -> None:
        """Global factory reset.

        This is only available for YubiKey Bio, which has a PIN that is shared between
        applications. This will factory reset the global PIN as well as the associated
        applications.
        """
        if not isinstance(self.backend, _ManagementSmartCardBackend):
            raise NotSupportedError("Device reset can only be performed over CCID")
        logger.debug("Performing device reset")
        self.backend.device_reset()
        logger.info("Device reset performed")
