from . import __version__ as ykman_version
from .logging_setup import log_sys_info
from .pcsc import list_readers, list_devices as list_ccid_devices
from .hid import list_otp_devices, list_ctap_devices

from yubikit.core import Version
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.management import ManagementSession, DeviceInfo
from yubikit.yubiotp import YubiOtpSession
from yubikit.piv import PivSession
from yubikit.oath import OathSession
from ykman.piv import get_piv_info
from ykman.openpgp import OpenPgpController, get_openpgp_info
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin


def mgmt_info(conn):
    try:
        raw_info = ManagementSession(conn).backend.read_config()
        info = DeviceInfo.parse(raw_info, Version(0, 0, 0))
        return [
            f"\t{info}",
            f"\tRawInfo: {raw_info.hex()}",
        ]
    except Exception as e:
        return [f"\tFailed to read device info: {e}"]


def piv_info(conn):
    try:
        piv = PivSession(conn)
        return ["\tPIV"] + [f"\t\t{ln}" for ln in get_piv_info(piv).splitlines() if ln]
    except Exception as e:
        return [f"\tPIV not accessible {e}"]


def openpgp_info(conn):
    try:
        openpgp = OpenPgpController(conn)
        return ["\tOpenPGP"] + [
            f"\t\t{ln}" for ln in get_openpgp_info(openpgp).splitlines() if ln
        ]
    except Exception as e:
        return [f"\tOpenPGP not accessible {e}"]


def oath_info(conn):
    try:
        oath = OathSession(conn)
        return [
            "\tOATH",
            f"\t\tOath version: {'.'.join('%d' % d for d in oath.version)}",
            f"\t\tPassword protected: {oath.locked}",
        ]
    except Exception as e:
        return [f"\tOATH not accessible {e}"]


def ccid_info():
    lines = []
    try:
        readers = list_readers()
        lines.append("Detected PC/SC readers:")
        for reader in readers:
            try:
                c = reader.createConnection()
                c.connect()
                c.disconnect()
                result = "Success"
            except Exception as e:
                result = e.__class__.__name__
            lines.append(f"\t{reader.name} (connect: {result})")
        lines.append("")
    except Exception as e:
        return [
            f"PC/SC failure: {e}",
            "",
        ]

    lines.append("Detected YubiKeys over PC/SC:")
    for dev in list_ccid_devices():
        lines.append(f"\t{dev!r}")
        try:
            with dev.open_connection(SmartCardConnection) as conn:
                lines.extend(mgmt_info(conn))
                lines.extend(piv_info(conn))
                lines.extend(oath_info(conn))
                lines.extend(openpgp_info(conn))
        except Exception as e:
            lines.append(f"\tPC/SC connection failure: {e}")
        lines.append("")

    lines.append("")
    return lines


def otp_info():
    lines = []
    lines.append("Detected YubiKeys over HID OTP:")
    for dev in list_otp_devices():
        lines.append(f"\t{dev!r}")
        with dev.open_connection(OtpConnection) as conn:
            lines.extend(mgmt_info(conn))
            otp = YubiOtpSession(conn)
            try:
                config = otp.get_config_state()
                lines.append(f"\tOTP: {config!r}")
            except ValueError as e:
                lines.append(f"\tCouldn't read OTP state: {e}")
        lines.append("")
    lines.append("")
    return lines


def fido_info():
    lines = []
    lines.append("Detected YubiKeys over HID FIDO:")
    for dev in list_ctap_devices():
        lines.append(f"\t{dev!r}")
        with dev.open_connection(FidoConnection) as conn:
            lines.append("CTAP device version: %d.%d.%d" % conn.device_version)
            lines.append(f"CTAPHID protocol version: {conn.version}")
            lines.append("Capabilities: %d" % conn.capabilities)
            lines.extend(mgmt_info(conn))
            try:
                ctap2 = Ctap2(conn)
                lines.append(f"\tCtap2Info: {ctap2.info.data!r}")
                if ctap2.info.options.get("clientPin"):
                    client_pin = ClientPin(ctap2)
                    lines.append(f"PIN retries: {client_pin.get_pin_retries()}")
                    bio_enroll = ctap2.info.options.get("bioEnroll")
                    if bio_enroll:
                        lines.append(
                            f"Fingerprint retries: {client_pin.get_uv_retries()}"
                        )
                    elif bio_enroll is False:
                        lines.append("Fingerprints: Not configured")
                else:
                    lines.append("PIN: Not configured")

            except (ValueError, CtapError) as e:
                lines.append(f"\tCouldn't get info: {e}")
        lines.append("")
    return lines


def get_diagnostics():
    lines = []
    lines.append(f"ykman: {ykman_version}")
    log_sys_info(lines.append)
    lines.append("")

    lines.extend(ccid_info())
    lines.extend(otp_info())
    lines.extend(fido_info())
    lines.append("End of diagnostics")

    return "\n".join(lines)
