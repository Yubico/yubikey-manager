from . import __version__ as ykman_version
from .logging_setup import log_sys_info
from .pcsc import list_readers, list_devices as list_ccid_devices
from .hid import list_otp_devices, list_ctap_devices

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
from fido2.ctap2 import Ctap2


def mgmt_info(conn):
    try:
        raw_info = ManagementSession(conn).backend.read_config()
        info = DeviceInfo.parse(raw_info, None)
        return [
            "\t%s" % info,
            "\tRawInfo: %s" % raw_info.hex(),
        ]
    except Exception as e:
        return ["\tFailed to read device info: %s" % e]


def piv_info(conn):
    try:
        piv = PivSession(conn)
        return ["\t%s" % l for l in get_piv_info(piv).splitlines() if l]
    except Exception as e:
        return ["\tPIV not accessible %s" % e]


def openpgp_info(conn):
    try:
        openpgp = OpenPgpController(conn)
        return ["\t%s" % l for l in get_openpgp_info(openpgp).splitlines() if l]
    except Exception as e:
        return ["\tOpenPGP not accessible %s" % e]


def oath_info(conn):
    try:
        oath = OathSession(conn)
        return [
            "\tOATH version: %s" % ".".join("%d" % d for d in oath.info.version),
            "\tPassword protected: %s" % oath.locked,
        ]
    except Exception as e:
        return ["\tOATH not accessible %s" % e]


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
            lines.append("\t%s (connect: %s)" % (reader.name, result))
        lines.append("")
    except Exception as e:
        lines.append("Failed connecting to PC/SC: %s" % e)
        return lines

    lines.append("Detected YubiKeys over PC/SC:")
    for dev in list_ccid_devices():
        lines.append("\t%r" % dev)
        try:
            with dev.open_connection(SmartCardConnection) as conn:
                lines.extend(mgmt_info(conn))
                lines.extend(piv_info(conn))
                lines.extend(oath_info(conn))
                lines.extend(openpgp_info(conn))
        except Exception as e:
            lines.append("\tFailed connecting to PC/SC: %s" % e)
        lines.append("")

    lines.append("")
    return lines


def otp_info():
    lines = []
    lines.append("Detected YubiKeys over HID OTP:")
    for dev in list_otp_devices():
        lines.append("\t%r" % dev)
        with dev.open_connection(OtpConnection) as conn:
            lines.extend(mgmt_info(conn))
            otp = YubiOtpSession(conn)
            try:
                config = otp.get_config_state()
                lines.append("\t%r" % config)
            except ValueError as e:
                lines.append("\tCouldn't read state: %s" % e)
        lines.append("")
    lines.append("")
    return lines


def fido_info():
    lines = []
    lines.append("Detected YubiKeys over HID FIDO:")
    for dev in list_ctap_devices():
        lines.append("\t%r" % dev)
        with dev.open_connection(FidoConnection) as conn:
            lines.extend(mgmt_info(conn))
            try:
                ctap2 = Ctap2(conn)
                lines.append("\tCTAP2 INFO: %r" % ctap2.info.data)
            except (ValueError, CtapError) as e:
                lines.append("\tCouldn't get info: %s" % e)
        lines.append("")
    return lines


def get_diagnostics():
    lines = []
    lines.append("ykman: %s" % ykman_version)
    log_sys_info(lines.append)
    lines.append("")

    lines.extend(ccid_info())
    lines.extend(otp_info())
    lines.extend(fido_info())
    lines.append("End of diagnostics")

    return "\n".join(lines)
