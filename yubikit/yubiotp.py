from __future__ import absolute_import

from .core import (
    AID,
    INTERFACE,
    BitflagEnum,
    bytes2int,
    NotSupportedError,
    BadResponseError,
)
from .core import ApplicationNotAvailableError
from .core.otp import check_crc, calculate_crc, OtpConnection, OtpProtocol
from .core.smartcard import SmartCardConnection, SmartCardProtocol
from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend

import struct
import re
from enum import unique, IntEnum


# TODO: Use it or remove it
@unique
class SLOT(IntEnum):
    ONE = 1
    TWO = 2


@unique
class CONFIG_SLOT(IntEnum):
    CONFIG_1 = 1  # First (default / V1) configuration
    NAV = 2  # V1 only
    CONFIG_2 = 3  # Second (V2) configuration
    UPDATE_1 = 4  # Update slot 1
    UPDATE_2 = 5  # Update slot 2
    SWAP = 6  # Swap slot 1 and 2
    NDEF_1 = 8  # Write NDEF record
    NDEF_2 = 9  # Write NDEF record for slot 2

    DEVICE_SERIAL = 0x10  # Device serial number
    DEVICE_CONFIG = 0x11  # Write device configuration record
    SCAN_MAP = 0x12  # Write scancode map
    YK4_CAPABILITIES = 0x13  # Read YK4 capabilities (device info) list
    YK4_SET_DEVICE_INFO = 0x15  # Write device info

    CHAL_OTP_1 = 0x20  # Write 6 byte challenge to slot 1, get Yubico OTP response
    CHAL_OTP_2 = 0x28  # Write 6 byte challenge to slot 2, get Yubico OTP response

    CHAL_HMAC_1 = 0x30  # Write 64 byte challenge to slot 1, get HMAC-SHA1 response
    CHAL_HMAC_2 = 0x38  # Write 64 byte challenge to slot 2, get HMAC-SHA1 response


class TKTFLAG(BitflagEnum):
    # Yubikey 1 and above
    TAB_FIRST = 0x01  # Send TAB before first part
    APPEND_TAB1 = 0x02  # Send TAB after first part
    APPEND_TAB2 = 0x04  # Send TAB after second part
    APPEND_DELAY1 = 0x08  # Add 0.5s delay after first part
    APPEND_DELAY2 = 0x10  # Add 0.5s delay after second part
    APPEND_CR = 0x20  # Append CR as final character

    # Yubikey 2 and above
    PROTECT_CFG2 = 0x80
    # Block update of config 2 unless config 2 is configured and has this bit set

    # Yubikey 2.1 and above
    OATH_HOTP = 0x40  # OATH HOTP mode

    # Yubikey 2.2 and above
    CHAL_RESP = 0x40  # Challenge-response enabled (both must be set)


class CFGFLAG(BitflagEnum):
    # Yubikey 1 and above
    SEND_REF = 0x01  # Send reference string (0..F) before data
    PACING_10MS = 0x04  # Add 10ms intra-key pacing
    PACING_20MS = 0x08  # Add 20ms intra-key pacing
    STATIC_TICKET = 0x20  # Static ticket generation

    # Yubikey 1 only
    TICKET_FIRST = 0x02  # Send ticket first (default is fixed part)
    ALLOW_HIDTRIG = 0x10  # Allow trigger through HID/keyboard

    # Yubikey 2 and above
    SHORT_TICKET = 0x02  # Send truncated ticket (half length)
    STRONG_PW1 = 0x10  # Strong password policy flag #1 (mixed case)
    STRONG_PW2 = 0x40  # Strong password policy flag #2 (subtitute 0..7 to digits)
    MAN_UPDATE = 0x80  # Allow manual (local) update of static OTP

    # Yubikey 2.1 and above
    OATH_HOTP8 = 0x02  # Generate 8 digits HOTP rather than 6 digits
    OATH_FIXED_MODHEX1 = 0x10  # First byte in fixed part sent as modhex
    OATH_FIXED_MODHEX2 = 0x40  # First two bytes in fixed part sent as modhex
    OATH_FIXED_MODHEX = 0x50  # Fixed part sent as modhex
    OATH_FIXED_MASK = 0x50  # Mask to get out fixed flags

    # Yubikey 2.2 and above
    CHAL_YUBICO = 0x20  # Challenge-response enabled - Yubico OTP mode
    CHAL_HMAC = 0x22  # Challenge-response enabled - HMAC-SHA1
    HMAC_LT64 = 0x04  # Set when HMAC message is less than 64 bytes
    CHAL_BTN_TRIG = 0x08  # Challenge-response operation requires button press


class EXTFLAG(BitflagEnum):
    SERIAL_BTN_VISIBLE = 0x01  # Serial number visible at startup (button press)
    SERIAL_USB_VISIBLE = 0x02  # Serial number visible in USB iSerial field
    SERIAL_API_VISIBLE = 0x04  # Serial number visible via API call

    # V2.3 flags only
    USE_NUMERIC_KEYPAD = 0x08  # Use numeric keypad for digits
    FAST_TRIG = 0x10  # Use fast trig if only cfg1 set
    ALLOW_UPDATE = 0x20
    # Allow update of existing configuration (selected flags + access code)
    DORMANT = 0x40  # Dormant config (woken up, flag removed, requires update flag)

    # V2.4/3.1 flags only
    LED_INV = 0x80  # LED idle state is off rather than on


# Flags valid for update
TKTFLAG_UPDATE_MASK = (
    TKTFLAG.TAB_FIRST
    | TKTFLAG.APPEND_TAB1
    | TKTFLAG.APPEND_TAB2
    | TKTFLAG.APPEND_DELAY1
    | TKTFLAG.APPEND_DELAY2
    | TKTFLAG.APPEND_CR
)
CFGFLAG_UPDATE_MASK = CFGFLAG.PACING_10MS | CFGFLAG.PACING_20MS
EXTFLAG_UPDATE_MASK = (
    EXTFLAG.SERIAL_BTN_VISIBLE
    | EXTFLAG.SERIAL_USB_VISIBLE
    | EXTFLAG.SERIAL_API_VISIBLE
    | EXTFLAG.USE_NUMERIC_KEYPAD
    | EXTFLAG.FAST_TRIG
    | EXTFLAG.ALLOW_UPDATE
    | EXTFLAG.DORMANT
    | EXTFLAG.LED_INV
)

# Data sizes
FIXED_SIZE = 16
UID_SIZE = 6
KEY_SIZE = 16
ACC_CODE_SIZE = 6
CONFIG_SIZE = 52
NDEF_DATA_SIZE = 54
HMAC_KEY_SIZE = 20
HMAC_CHALLENGE_SIZE = 64
HMAC_RESPONSE_SIZE = 20
SCAN_CODES_SIZE = FIXED_SIZE + UID_SIZE + KEY_SIZE


DEFAULT_NDEF_URI = "https://my.yubico.com/yk/#"

NDEF_URL_PREFIXES = (
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    "tel:",
    "mailto:",
    "ftp://anonymous:anonymous@",
    "ftp://ftp.",
    "ftps://",
    "sftp://",
    "smb://",
    "nfs://",
    "ftp://",
    "dav://",
    "news:",
    "telnet://",
    "imap:",
    "rtsp://",
    "urn:",
    "pop:",
    "sip:",
    "sips:",
    "tftp:",
    "btspp://",
    "btl2cap://",
    "btgoep://",
    "tcpobex://",
    "irdaobex://",
    "file://",
    "urn:epc:id:",
    "urn:epc:tag:",
    "urn:epc:pat:",
    "urn:epc:raw:",
    "urn:epc:",
    "urn:nfc:",
)


def _build_config(fixed, uid, key, ext, tkt, cfg, acc_code=None):
    buf = (
        fixed.ljust(FIXED_SIZE, b"\0")
        + uid
        + key
        + (acc_code or b"\0" * ACC_CODE_SIZE)
        + struct.pack(">BBBB", len(fixed), ext, tkt, cfg)
        + b"\0\0"  # RFU
    )
    return buf + struct.pack("<H", 0xFFFF & ~calculate_crc(buf))


def _build_update(ext, tkt, cfg, acc_code=None):
    if ext & ~EXTFLAG_UPDATE_MASK != 0:
        raise ValueError("Unsupported ext flags for update")
    if tkt & ~TKTFLAG_UPDATE_MASK != 0:
        raise ValueError("Unsupported tkt flags for update")
    if cfg & ~CFGFLAG_UPDATE_MASK != 0:
        raise ValueError("Unsupported cfg flags for update")
    return _build_config(
        b"", b"\0" * UID_SIZE, b"\0" * KEY_SIZE, ext, tkt, cfg, acc_code
    )


def _build_ndef_config(uri):
    uri = uri or DEFAULT_NDEF_URI
    for i, prefix in enumerate(NDEF_URL_PREFIXES):
        if uri.startswith(prefix):
            id_code = i + 1
            uri = uri[len(prefix) :]
            break
    else:
        id_code = 0
    uri_bytes = uri.encode("utf8")
    data_len = 1 + len(uri_bytes)
    if data_len > NDEF_DATA_SIZE:
        raise ValueError("URI payload too large")
    return struct.pack("<BBB", data_len, ord("U"), id_code) + uri_bytes.ljust(
        NDEF_DATA_SIZE - 1, b"\0"
    )


@unique
class CFGSTATE(BitflagEnum):
    # Bits in touch_level
    SLOT1_VALID = 0x01  # configuration 1 is valid (from firmware 2.1)
    SLOT2_VALID = 0x02  # configuration 2 is valid (from firmware 2.1)
    SLOT1_TOUCH = 0x04  # configuration 1 requires touch (from firmware 3.0)
    SLOT2_TOUCH = 0x08  # configuration 2 requires touch (from firmware 3.0)
    LED_INV = 0x10  # LED behavior is inverted (EXTFLAG_LED_INV mirror)


def _shorten_hmac_key(key):
    h = SHA1()  # nosec
    if len(key) > h.block_size:
        h = Hash(h, default_backend())
        h.update(key)
        key = h.finalize()
    elif len(key) > HMAC_KEY_SIZE:
        raise NotSupportedError(
            "Key lengths > {} bytes not supported".format(HMAC_KEY_SIZE)
        )
    return key


class SlotConfiguration(object):
    def __init__(self):
        self._fixed = b""
        self._uid = b"\0" * UID_SIZE
        self._key = b"\0" * KEY_SIZE
        self._flags = {}

        self._update_flags(EXTFLAG.SERIAL_API_VISIBLE, True)
        self._update_flags(EXTFLAG.ALLOW_UPDATE, True)

    def _update_flags(self, flag, value):
        flag_key = type(flag)
        flags = self._flags.get(flag_key, 0)
        self._flags[flag_key] = flags | flag if value else flags & ~flag

    def is_supported_by(self, version):
        return True

    def get_config(self, acc_code=None):
        return _build_config(
            self._fixed,
            self._uid,
            self._key,
            self._flags.get(EXTFLAG, 0),
            self._flags.get(TKTFLAG, 0),
            self._flags.get(CFGFLAG, 0),
            acc_code,
        )

    def serial_api_visible(self, value):
        self._update_flags(EXTFLAG.SERIAL_API_VISIBLE, value)
        return self

    def serial_usb_visible(self, value):
        self._update_flags(EXTFLAG.SERIAL_USB_VISIBLE, value)
        return self

    def allow_update(self, value):
        self._update_flags(EXTFLAG.ALLOW_UPDATE, value)
        return self

    def dormant(self, value):
        self._update_flags(EXTFLAG.DORMANT, value)
        return self

    def invert_led(self, value):
        self._update_flags(EXTFLAG.LED_INV, value)
        return self

    def protect_slot2(self, value):
        self._update_flags(TKTFLAG.PROTECT_CFG2, value)
        return self


class HmacSha1SlotConfiguration(SlotConfiguration):
    def __init__(self, key):
        super(HmacSha1SlotConfiguration, self).__init__()

        key = _shorten_hmac_key(key)

        # Key is packed into key and uid
        self._key = key[:KEY_SIZE].ljust(KEY_SIZE, b"\0")
        self._uid = key[KEY_SIZE:].ljust(UID_SIZE, b"\0")

        self._update_flags(TKTFLAG.CHAL_RESP, True)
        self._update_flags(CFGFLAG.CHAL_HMAC, True)
        self._update_flags(CFGFLAG.HMAC_LT64, True)

    def is_supported_by(self, version):
        return version >= (2, 2, 0)

    def require_touch(self, value):
        self._update_flags(CFGFLAG.CHAL_BTN_TRIG, value)
        return self

    def lt64(self, value):
        self._update_flags(CFGFLAG.HMAC_LT64, value)
        return self


class KeyboardSlotConfiguration(SlotConfiguration):
    def __init__(self):
        super(KeyboardSlotConfiguration, self).__init__()
        self._update_flags(TKTFLAG.APPEND_CR, True)
        self._update_flags(EXTFLAG.FAST_TRIG, True)

    def append_cr(self, value):
        self._update_flags(TKTFLAG.APPEND_CR, value)
        return self

    def fast_trigger(self, value):
        self._update_flags(EXTFLAG.FAST_TRIG, value)
        return self

    def pacing(self, pacing_10ms=False, pacing_20ms=False):
        self._update_flags(CFGFLAG.PACING_10MS, pacing_10ms)
        self._update_flags(CFGFLAG.PACING_20MS, pacing_20ms)
        return self

    def use_numeric(self, value):
        self._update_flags(EXTFLAG.USE_NUMERIC_KEYPAD, value)
        return self


class HotpSlotConfiguration(KeyboardSlotConfiguration):
    def __init__(self, key):
        super(HotpSlotConfiguration, self).__init__()

        key = _shorten_hmac_key(key)

        # Key is packed into key and uid
        self._key = key[:KEY_SIZE].ljust(KEY_SIZE, b"\0")
        self._uid = key[KEY_SIZE:].ljust(UID_SIZE, b"\0")

        self._update_flags(TKTFLAG.OATH_HOTP, True)
        self._update_flags(CFGFLAG.OATH_FIXED_MODHEX2, True)

    def is_supported_by(self, version):
        return version >= (2, 2, 0)

    def digits8(self, value):
        self._update_flags(CFGFLAG.OATH_HOTP8, value)
        return self

    def token_id(self, token_id, fixed_modhex1=False, fixed_modhex2=True):
        if len(token_id) > FIXED_SIZE:
            raise ValueError("token_id must be <= {} bytes".format(FIXED_SIZE))

        self._fixed = token_id
        self._update_flags(CFGFLAG.OATH_FIXED_MODHEX1, fixed_modhex1)
        self._update_flags(CFGFLAG.OATH_FIXED_MODHEX2, fixed_modhex2)
        return self

    def imf(self, imf):
        if not (imf % 16 == 0 or 0 <= imf <= 0xFFFF0):
            raise ValueError(
                "imf should be between {} and {}, evenly dividable by 16".format(
                    0, 0xFFFF0
                )
            )
        self._uid = self._uid[:4] + struct.pack(">H", imf >> 4)
        return self


class StaticPasswordSlotConfiguration(KeyboardSlotConfiguration):
    def __init__(self, scan_codes):
        super(StaticPasswordSlotConfiguration, self).__init__()

        if len(scan_codes) > SCAN_CODES_SIZE:
            raise NotSupportedError("Password is too long")

        # Scan codes are packed into fixed, key and uid
        scan_codes = scan_codes.ljust(SCAN_CODES_SIZE, b"\0")
        self._fixed = scan_codes[:FIXED_SIZE]
        self._key = scan_codes[FIXED_SIZE : FIXED_SIZE + KEY_SIZE]
        self._uid = scan_codes[FIXED_SIZE + KEY_SIZE :]

        self._update_flags(CFGFLAG.SHORT_TICKET, True)

    def is_supported_by(self, version):
        return version >= (2, 2, 0)


class YubiOtpSlotConfiguration(KeyboardSlotConfiguration):
    def __init__(self, fixed, uid, key):
        super(YubiOtpSlotConfiguration, self).__init__()

        if len(fixed) > FIXED_SIZE:
            raise ValueError("fixed must be <= {} bytes".format(FIXED_SIZE))

        if len(uid) != UID_SIZE:
            raise ValueError("uid must be {} bytes".format(UID_SIZE))

        if len(key) != KEY_SIZE:
            raise ValueError("key must be {} bytes".format(KEY_SIZE))

        self._fixed = fixed
        self._uid = uid
        self._key = key

    def tabs(self, before=False, after_first=False, after_second=False):
        self._update_flags(TKTFLAG.TAB_FIRST, before)
        self._update_flags(TKTFLAG.APPEND_TAB1, after_first)
        self._update_flags(TKTFLAG.APPEND_TAB2, after_second)
        return self

    def delay(self, after_first=False, after_second=False):
        self._update_flags(TKTFLAG.APPEND_DELAY1, after_first)
        self._update_flags(TKTFLAG.APPEND_DELAY2, after_second)
        return self

    def send_reference(self, value):
        self._update_flags(CFGFLAG.SEND_REF, value)
        return self


class StaticTicketSlotConfiguration(KeyboardSlotConfiguration):
    def __init__(self, fixed, uid, key):
        super(StaticTicketSlotConfiguration, self).__init__()

        if len(fixed) > FIXED_SIZE:
            raise ValueError("fixed must be <= {} bytes".format(FIXED_SIZE))

        if len(uid) != UID_SIZE:
            raise ValueError("uid must be {} bytes".format(UID_SIZE))

        if len(key) != KEY_SIZE:
            raise ValueError("key must be {} bytes".format(KEY_SIZE))

        self._fixed = fixed
        self._uid = uid
        self._key = key

        self._update_flags(CFGFLAG.STATIC_TICKET, True)

    def short_ticket(self, value):
        self._update_flags(CFGFLAG.SHORT_TICKET, value)
        return self

    def strong_password(self, upper_case=False, digit=False, special=False):
        self._update_flags(CFGFLAG.STRONG_PW1, upper_case)
        self._update_flags(CFGFLAG.STRONG_PW2, digit or special)
        self._update_flags(CFGFLAG.SEND_REF, special)
        return self

    def manual_update(self, value):
        self._update_flags(CFGFLAG.MAN_UPDATE, value)
        return self


class UpdateConfiguration(KeyboardSlotConfiguration):
    def __init__(self):
        super(UpdateConfiguration, self).__init__()

        self._fixed = b"\0" * FIXED_SIZE
        self._uid = b"\0" * UID_SIZE
        self._key = b"\0" * KEY_SIZE

    def is_supported_by(self, version):
        return version >= (2, 2, 0)

    def _update_flags(self, flag, value):
        # NB: All EXT flags are allowed
        if isinstance(flag, TKTFLAG):
            if not TKTFLAG_UPDATE_MASK & flag:
                raise ValueError("Unsupported TKT flag for update")
        elif isinstance(flag, CFGFLAG):
            if not CFGFLAG_UPDATE_MASK & flag:
                raise ValueError("Unsupported CFG flag for update")
        super(UpdateConfiguration, self)._update_flags(flag, value)

    def protect_slot2(self, value):
        raise ValueError("protect_slot2 cannot be applied to UpdateConfiguration")

    def tabs(self, before=False, after_first=False, after_second=False):
        self._update_flags(TKTFLAG.TAB_FIRST, before)
        self._update_flags(TKTFLAG.APPEND_TAB1, after_first)
        self._update_flags(TKTFLAG.APPEND_TAB2, after_second)
        return self

    def delay(self, after_first=False, after_second=False):
        self._update_flags(TKTFLAG.APPEND_DELAY1, after_first)
        self._update_flags(TKTFLAG.APPEND_DELAY2, after_second)
        return self


class ConfigState(object):
    def __init__(self, version, touch_level):
        self.version = version
        self.flags = sum(CFGSTATE) & touch_level

    def is_configured(self, slot):
        if self.version < (2, 1, 0):
            raise NotSupportedError("Configuration state requires YubiKey 2.1 or later")
        return self.flags & (CFGSTATE.SLOT1_VALID, CFGSTATE.SLOT2_VALID)[slot - 1] != 0

    def requires_touch(self, slot):
        if self.version < (3, 0, 0):
            raise NotSupportedError("Touch state requires YubiKey 3.0 or later")
        return self.flags & (CFGSTATE.SLOT1_TOUCH, CFGSTATE.SLOT2_TOUCH)[slot - 1] != 0

    def is_led_inverted(self):
        return self.flags & CFGSTATE.LED_INV != 0


class _YubiOtpOtpBackend(object):
    def __init__(self, protocol):
        self.protocol = protocol

    def close(self):
        self.protocol.close()

    def write_update(self, slot, data):
        return self.protocol.send_and_receive(slot, data)

    def send_and_receive(self, slot, data, expected_len, event=None, on_keepalive=None):
        response = self.protocol.send_and_receive(slot, data, event, on_keepalive)
        if check_crc(response[: expected_len + 2]):
            return response[:expected_len]
        raise BadResponseError("Invalid CRC")


INS_CONFIG = 0x01


class _YubiOtpSmartCardBackend(object):
    def __init__(self, protocol):
        self.protocol = protocol

    def close(self):
        self.protocol.close()

    def write_update(self, slot, data):
        return self.protocol.send_apdu(0, INS_CONFIG, slot, 0, data)

    def send_and_receive(self, slot, data, expected_len, event=None, on_keepalive=None):
        response = self.protocol.send_apdu(0, INS_CONFIG, slot, 0, data)
        if expected_len == len(response):
            return response
        raise BadResponseError("Unexpected response length")


MGMT_VERSION_PATTERN = re.compile(r"\b\d+.\d.\d\b")


class YubiOtpSession(object):
    def __init__(self, connection):
        if isinstance(connection, OtpConnection):
            protocol = OtpProtocol(connection)
            self._status = protocol.read_status()
            self._version = tuple(self._status[:3])
            self.backend = _YubiOtpOtpBackend(protocol)
        elif isinstance(connection, SmartCardConnection):
            protocol = SmartCardProtocol(connection)
            mgmt_version = None
            if connection.interface == INTERFACE.NFC:
                # This version is more reliable over NFC
                try:
                    protocol.select(AID.MGMT)
                    select_str = protocol.select(AID.MGMT).decode()
                    mgmt_version = tuple(
                        int(d)
                        for d in MGMT_VERSION_PATTERN.search(select_str)
                        .group()
                        .split(".")
                    )
                except ApplicationNotAvailableError:
                    pass  # Not available (probably NEO), get version from status

            self._status = protocol.select(AID.OTP)
            otp_version = tuple(self._status[:3])
            if mgmt_version and mgmt_version[0] == 3:
                # NEO reports the highest of these two
                self._version = max(mgmt_version, otp_version)
            else:
                self._version = mgmt_version or otp_version
            protocol.enable_touch_workaround(self._version)
            self.backend = _YubiOtpSmartCardBackend(protocol)
        else:
            raise TypeError("Unsupported connection type")

    def close(self):
        self.backend.close()

    @property
    def version(self):
        return self._version

    def get_serial(self):
        return bytes2int(
            self.backend.send_and_receive(CONFIG_SLOT.DEVICE_SERIAL, b"", 4)
        )

    def get_config_state(self):
        return ConfigState(self.version, struct.unpack("<H", self._status[4:6])[0])

    def _write_config(self, slot, config, cur_acc_code):
        self._status = self.backend.write_update(
            slot, config + (cur_acc_code or b"\0" * ACC_CODE_SIZE)
        )

    def put_configuration(self, slot, configuration, acc_code=None, cur_acc_code=None):
        if not configuration.is_supported_by(self.version):
            raise NotSupportedError(
                "This configuration is not supported on this YubiKey version"
            )
        self._write_config(
            (CONFIG_SLOT.CONFIG_1, CONFIG_SLOT.CONFIG_2)[slot - 1],
            configuration.get_config(acc_code),
            cur_acc_code,
        )

    def update_configuration(
        self, slot, configuration, acc_code=None, cur_acc_code=None
    ):
        if not configuration.is_supported_by(self.version):
            raise NotSupportedError(
                "This configuration is not supported on this YubiKey version"
            )
        if acc_code != cur_acc_code and (4, 3, 2) <= self.version < (4, 3, 6):
            raise NotSupportedError(
                "The access code cannot be updated on this YubiKey. "
                "Instead, delete the slot and configure it anew."
            )
        self._write_config(
            (CONFIG_SLOT.UPDATE_1, CONFIG_SLOT.UPDATE_2)[slot - 1],
            configuration.get_config(acc_code),
            cur_acc_code,
        )

    def swap_slots(self):
        self._write_config(CONFIG_SLOT.SWAP, b"", None)

    def delete_slot(self, slot, cur_acc_code=None):
        self._write_config(
            (CONFIG_SLOT.CONFIG_1, CONFIG_SLOT.CONFIG_2)[slot - 1],
            b"\0" * CONFIG_SIZE,
            cur_acc_code,
        )

    def set_ndef_configuration(self, slot, uri=None, cur_acc_code=None):
        self._write_config(
            (CONFIG_SLOT.NDEF_1, CONFIG_SLOT.NDEF_2)[slot - 1],
            _build_ndef_config(uri),
            cur_acc_code,
        )

    def calculate_hmac_sha1(self, slot, challenge, event=None, on_keepalive=None):
        if self.version < (2, 2, 0):
            raise NotSupportedError("This operation requires YubiKey 2.2 or later")

        # Pad challenge with byte different from last
        challenge = challenge.ljust(
            HMAC_CHALLENGE_SIZE, b"\1" if challenge.endswith(b"\0") else b"\0"
        )
        return self.backend.send_and_receive(
            (CONFIG_SLOT.CHAL_HMAC_1, CONFIG_SLOT.CHAL_HMAC_2)[slot - 1],
            challenge,
            HMAC_RESPONSE_SIZE,
            event,
            on_keepalive,
        )
