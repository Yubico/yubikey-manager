from __future__ import absolute_import

from .core import (
    bytes2int,
    int2bytes,
    Tlv,
    BitflagEnum,
    AID,
    PID,
    INTERFACE,
    APPLICATION,
    FORM_FACTOR,
    TRANSPORT,
    NotSupportedError,
    BadResponseError,
)
from .core.otp import check_crc, OtpConnection, OtpProtocol
from .core.smartcard import SmartCardConnection, SmartCardProtocol

from fido2.ctap import CtapDevice

from enum import IntEnum, unique
from collections import namedtuple
import re
import struct

VERSION_PATTERN = re.compile(r"\b\d+.\d.\d\b")


SLOT_DEVICE_CONFIG = 0x11
SLOT_YK4_CAPABILITIES = 0x13
SLOT_YK4_SET_DEVICE_INFO = 0x15

INS_READ_CONFIG = 0x1D
INS_WRITE_CONFIG = 0x1C
INS_SET_MODE = 0x16
P1_DEVICE_CONFIG = 0x11

CTAP_VENDOR_FIRST = 0x40
CTAP_YUBIKEY_DEVICE_CONFIG = CTAP_VENDOR_FIRST
CTAP_READ_CONFIG = CTAP_VENDOR_FIRST + 2
CTAP_WRITE_CONFIG = CTAP_VENDOR_FIRST + 3


@unique
class DEVICE_FLAG(BitflagEnum):
    REMOTE_WAKEUP = 0x40
    EJECT = 0x80


class _ManagementOtpBackend(OtpProtocol):
    def __init__(self, otp_connection):
        super(_ManagementOtpBackend, self).__init__(otp_connection)
        self.version = tuple(self.read_status()[:3])

    def set_mode(self, data):
        self.send_and_receive(SLOT_DEVICE_CONFIG, data)

    def read_config(self):
        response = self.send_and_receive(SLOT_YK4_CAPABILITIES)
        r_len = response[0]
        if check_crc(response[: r_len + 1 + 2]):
            return response[: r_len + 1]
        raise BadResponseError("Invalid checksum")

    def write_config(self, config):
        self.send_and_receive(SLOT_YK4_SET_DEVICE_INFO, config)


class _ManagementSmartCardBackend(SmartCardProtocol):
    def __init__(self, smartcard_connection):
        super(_ManagementSmartCardBackend, self).__init__(smartcard_connection)
        select_str = self.select(AID.MGMT).decode()
        self.version = tuple(
            int(d) for d in VERSION_PATTERN.search(select_str).group().split(".")
        )

    def set_mode(self, data):
        if self.version[0] == 3:
            # Use the OTP Application to set mode
            self.select(AID.OTP)
            self.send_apdu(0, 0x01, SLOT_DEVICE_CONFIG, 0, data)
            # Workaround to "de-select" on NEO
            self.connection.send_and_receive(b"\xa4\x04\x00\x08")
            self.select(AID.MGMT)
        else:
            self.send_apdu(0, INS_SET_MODE, P1_DEVICE_CONFIG, 0, data)

    def read_config(self):
        return self.send_apdu(0, INS_READ_CONFIG, 0, 0)

    def write_config(self, config):
        self.send_apdu(0, INS_WRITE_CONFIG, 0, 0, config)


class _ManagementCtapBackend(object):
    def __init__(self, ctap_device):
        self.ctap = ctap_device
        version = ctap_device.device_version
        if version[0] < 4:  # Prior to YK4 this was not firmware version
            version = (3, 0, 0)  # Guess
        self.version = version

    def close(self):
        self.ctap.close()

    def set_mode(self, data):
        self.ctap.call(CTAP_YUBIKEY_DEVICE_CONFIG, data)

    def read_config(self):
        return self.ctap.call(CTAP_READ_CONFIG)

    def write_config(self, config):
        self.ctap.call(CTAP_WRITE_CONFIG, config)


@unique
class TAG(IntEnum):
    USB_SUPPORTED = 0x01
    SERIAL = 0x02
    USB_ENABLED = 0x03
    FORM_FACTOR = 0x04
    VERSION = 0x05
    AUTO_EJECT_TIMEOUT = 0x06
    CHALRESP_TIMEOUT = 0x07
    DEVICE_FLAGS = 0x08
    APP_VERSIONS = 0x09
    CONFIG_LOCK = 0x0A
    UNLOCK = 0x0B
    REBOOT = 0x0C
    NFC_SUPPORTED = 0x0D
    NFC_ENABLED = 0x0E


class DeviceConfig(
    namedtuple(
        "DeviceConfig",
        [
            "enabled_applications",
            "auto_eject_timeout",
            "challenge_response_timeout",
            "device_flags",
        ],
    )
):
    __slots__ = ()

    def get_bytes(self, reboot, cur_lock_code=None, new_lock_code=None):
        buf = b""
        if reboot:
            buf += Tlv(TAG.REBOOT)
        if cur_lock_code:
            buf += Tlv(TAG.UNLOCK, cur_lock_code)
        usb_enabled = self.enabled_applications.get(INTERFACE.USB)
        if usb_enabled is not None:
            buf += Tlv(TAG.USB_ENABLED, int2bytes(usb_enabled, 2))
        nfc_enabled = self.enabled_applications.get(INTERFACE.NFC)
        if nfc_enabled is not None:
            buf += Tlv(TAG.NFC_ENABLED, int2bytes(nfc_enabled, 2))
        if self.auto_eject_timeout is not None:
            buf += Tlv(TAG.AUTO_EJECT_TIMEOUT, int2bytes(self.auto_eject_timeout, 2))
        if self.challenge_response_timeout is not None:
            buf += Tlv(TAG.CHALRESP_TIMEOUT, int2bytes(self.challenge_response_timeout))
        if self.device_flags is not None:
            buf += Tlv(TAG.DEVICE_FLAGS, int2bytes(self.device_flags))
        if new_lock_code:
            buf += Tlv(TAG.CONFIG_LOCK, new_lock_code)
        if len(buf) > 0xFF:
            raise NotSupportedError("DeviceConfiguration too large")
        return int2bytes(len(buf)) + buf


class DeviceInfo(
    namedtuple(
        "DeviceInfo",
        [
            "config",
            "serial",
            "version",
            "form_factor",
            "supported_applications",
            "is_locked",
        ],
    )
):
    def has_interface(self, interface):
        return interface in self.supported_applications

    @classmethod
    def parse(cls, encoded, default_version):
        if len(encoded) - 1 != encoded[0]:
            raise BadResponseError("Invalid length")
        data = Tlv.parse_dict(encoded[1:])
        locked = data.get(TAG.CONFIG_LOCK) == b"\1"
        serial = bytes2int(data.get(TAG.SERIAL, b"\0")) or None
        form_factor = FORM_FACTOR.from_code(bytes2int(data.get(TAG.FORM_FACTOR, b"\0")))
        version = tuple(data.get(TAG.VERSION, default_version))
        auto_eject_to = bytes2int(data.get(TAG.AUTO_EJECT_TIMEOUT, b"\0"))
        chal_resp_to = bytes2int(data.get(TAG.CHALRESP_TIMEOUT, b"\0"))
        flags = bytes2int(data.get(TAG.DEVICE_FLAGS, b"\0"))

        supported = {}
        enabled = {}

        if version == (4, 2, 4):  # Doesn't report correctly
            supported[INTERFACE.USB] = 0x3F
        else:
            supported[INTERFACE.USB] = bytes2int(data.get(TAG.USB_SUPPORTED))
        if TAG.USB_ENABLED in data:  # From YK 5.0.0
            enabled[INTERFACE.USB] = bytes2int(data.get(TAG.USB_ENABLED))
        if TAG.NFC_SUPPORTED in data:  # YK with NFC
            supported[INTERFACE.NFC] = bytes2int(data[TAG.NFC_SUPPORTED])
            enabled[INTERFACE.NFC] = bytes2int(data[TAG.NFC_ENABLED])

        return cls(
            DeviceConfig(enabled, auto_eject_to, chal_resp_to, flags),
            serial,
            version,
            form_factor,
            supported,
            locked,
        )


class Mode(object):
    _modes = [
        TRANSPORT.OTP,  # 0x00
        TRANSPORT.CCID,  # 0x01
        TRANSPORT.OTP | TRANSPORT.CCID,  # 0x02
        TRANSPORT.FIDO,  # 0x03
        TRANSPORT.OTP | TRANSPORT.FIDO,  # 0x04
        TRANSPORT.FIDO | TRANSPORT.CCID,  # 0x05
        TRANSPORT.OTP | TRANSPORT.FIDO | TRANSPORT.CCID,  # 0x06
    ]

    def __init__(self, transports):
        try:
            self.code = self._modes.index(transports)
            self._transports = transports
        except ValueError:
            raise ValueError("Invalid mode!")

    @property
    def transports(self):
        return self._transports

    def has_transport(self, transport):
        return TRANSPORT.has(self._transports, transport)

    def __eq__(self, other):
        return other is not None and self.code == other.code

    def __ne__(self, other):
        return other is None or self.code != other.code

    def __str__(self):
        return "+".join((t.name for t in TRANSPORT.split(self._transports)))

    @classmethod
    def from_code(cls, code):
        code = code & 0b00000111
        return cls(cls._modes[code])

    @classmethod
    def from_pid(cls, pid):
        return cls(PID(pid).get_transports())

    __hash__ = None


class ManagementSession(object):
    def __init__(self, connection):
        if isinstance(connection, OtpConnection):
            self.backend = _ManagementOtpBackend(connection)
        elif isinstance(connection, SmartCardConnection):
            self.backend = _ManagementSmartCardBackend(connection)
        elif isinstance(connection, CtapDevice):
            self.backend = _ManagementCtapBackend(connection)
        else:
            raise TypeError("Unsupported connection type")
        if self.version < (3, 0, 0):
            raise NotSupportedError("ManagementSession requires YubiKey 3 or later")

    def close(self):
        self.backend.close()

    @property
    def version(self):
        return self.backend.version

    def read_device_info(self):
        if self.version < (4, 1, 0):
            raise NotSupportedError("Operation requires YubiKey 4.1 or later")
        return DeviceInfo.parse(self.backend.read_config(), self.version)

    def write_device_config(
        self, config=None, reboot=False, cur_lock_code=None, new_lock_code=None
    ):
        if self.version < (5, 0, 0):
            raise NotSupportedError("Operation requires YubiKey 5 or later")

        config = config or DeviceConfig({}, None, None, None)
        self.backend.write_config(
            config.get_bytes(reboot, cur_lock_code, new_lock_code)
        )

    def set_mode(self, mode, chalresp_timeout=0, auto_eject_timeout=0):
        if self.version < (3, 0, 0):
            raise NotSupportedError("Changing mode requires YubiKey 3 or later")
        if self.version >= (5, 0, 0):
            # Translate into DeviceConfig
            usb_enabled = 0
            if mode.has_transport(TRANSPORT.OTP):
                usb_enabled |= APPLICATION.OTP
            if mode.has_transport(TRANSPORT.CCID):
                usb_enabled |= APPLICATION.OATH | APPLICATION.PIV | APPLICATION.OPGP
            if mode.has_transport(TRANSPORT.FIDO):
                usb_enabled |= APPLICATION.U2F | APPLICATION.FIDO2
            self.write_device_config(
                DeviceConfig(
                    {INTERFACE.USB: usb_enabled},
                    auto_eject_timeout,
                    chalresp_timeout,
                    None,
                )
            )
        else:
            self.backend.set_mode(
                struct.pack(">BBH", mode.code, chalresp_timeout, auto_eject_timeout)
            )
