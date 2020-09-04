from __future__ import absolute_import

from .core import AID, BitflagEnum, bytes2int, NotSupportedError, BadResponseError
from .core.otp import check_crc, calculate_crc, OtpConnection, OtpApplication
from .core.iso7816 import Iso7816Connection, Iso7816Application, ApduError

import struct
from enum import unique, IntEnum


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


class _YkCfgOtpBackend(object):
    def __init__(self, app):
        self.app = app

    def close(self):
        self.app.close()

    def write_update(self, slot, data):
        return self.app.transceive(slot, data)

    def transceive(self, slot, data, expected_len, event=None, on_keepalive=None):
        response = self.app.transceive(slot, data, event, on_keepalive)
        if check_crc(response[: expected_len + 2]):
            return response[:expected_len]
        raise BadResponseError("Invalid CRC")


INS_CONFIG = 0x01


class _YkCfgIso7816Backend(object):
    def __init__(self, app):
        self.app = app

    def close(self):
        self.app.close()

    def write_update(self, slot, data):
        return self.app.send_apdu(0, INS_CONFIG, slot, 0, data)

    def transceive(self, slot, data, expected_len, event=None, on_keepalive=None):
        response = self.app.send_apdu(0, INS_CONFIG, slot, 0, data)
        if expected_len == len(response):
            return response
        raise BadResponseError("Unexpected response length")


class YkCfgApplication(object):
    def __init__(self, connection):
        if isinstance(connection, OtpConnection):
            app = OtpApplication(connection)
            self._status = app.read_status()
            self._version = tuple(self._status[:3])
            self.backend = _YkCfgOtpBackend(app)
        elif isinstance(connection, Iso7816Connection):
            mgmt_version = None
            try:  # This version number is more reliable for NEO
                from .mgmt import ManagementApplication

                mgmt = ManagementApplication(connection)
                mgmt_version = mgmt.version
                if mgmt_version < (4, 0, 0):
                    # Workaround to "de-select" on NEO
                    connection.transceive(b"\xa4\x04\x00\x08")
            except ApduError:
                pass  # Not available, get version from status

            app = Iso7816Application(AID.OTP, connection)
            self._status = app.select()
            otp_version = tuple(self._status[:3])
            if mgmt_version and mgmt_version[0] == 3:
                # NEO reports the highest of these two
                self._version = max(mgmt_version, otp_version)
            else:
                self._version = mgmt_version or otp_version
            self.backend = _YkCfgIso7816Backend(app)
        else:
            raise TypeError("Unsupported connection type")

    def close(self):
        self.backend.close()

    @property
    def version(self):
        return self._version

    def get_serial(self):
        return bytes2int(self.backend.transceive(CONFIG_SLOT.DEVICE_SERIAL, b"", 4))

    def get_config_state(self):
        return ConfigState(self.version, struct.unpack("<H", self._status[4:6])[0])

    def _write_config(self, slot, config, cur_acc_code):
        self._status = self.backend.write_update(
            slot, config + (cur_acc_code or b"\0" * ACC_CODE_SIZE)
        )

    def write_configuration(
        self, slot, fixed, uid, key, ext, tkt, cfg, acc_code=None, cur_acc_code=None
    ):
        self._write_config(
            (CONFIG_SLOT.CONFIG_1, CONFIG_SLOT.CONFIG_2)[slot - 1],
            _build_config(fixed, uid, key, ext, tkt, cfg, acc_code),
            cur_acc_code,
        )

    def update_configuration(
        self, slot, ext, tkt, cfg, acc_code=None, cur_acc_code=None
    ):
        self._write_config(
            (CONFIG_SLOT.UPDATE_1, CONFIG_SLOT.UPDATE_2)[slot - 1],
            _build_update(ext, tkt, cfg, acc_code),
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

    def configure_ndef(self, slot, uri, cur_acc_code=None):
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
        return self.backend.transceive(
            (CONFIG_SLOT.CHAL_HMAC_1, CONFIG_SLOT.CHAL_HMAC_2)[slot - 1],
            challenge,
            HMAC_RESPONSE_SIZE,
            event,
            on_keepalive,
        )

    def set_hmac_sha1_key(self, slot, secret, require_touch=False):
        if self.version < (2, 2, 0):
            raise NotSupportedError("This operation requires YubiKey 2.2 or later")
        if not secret or len(secret) > HMAC_KEY_SIZE:
            raise ValueError("Secret must be <= 20 bytes")
        secret = secret.ljust(KEY_SIZE + UID_SIZE, b"\0")

        cfg_flags = CFGFLAG.CHAL_HMAC | CFGFLAG.HMAC_LT64
        if require_touch:
            cfg_flags |= CFGFLAG.CHAL_BTN_TRIG

        self.write_configuration(
            slot,
            b"",
            secret[KEY_SIZE:],
            secret[:KEY_SIZE],
            EXTFLAG.SERIAL_API_VISIBLE | EXTFLAG.ALLOW_UPDATE,
            TKTFLAG.CHAL_RESP,
            cfg_flags,
        )
