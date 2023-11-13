from . import __version__ as ykman_version
from .util import get_windows_version
from .pcsc import list_readers, list_devices as list_ccid_devices
from .hid import list_otp_devices, list_ctap_devices
from .piv import get_piv_info
from .openpgp import get_openpgp_info
from .hsmauth import get_hsmauth_info

from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.management import ManagementSession
from yubikit.yubiotp import YubiOtpSession
from yubikit.piv import PivSession
from yubikit.oath import OathSession
from yubikit.openpgp import OpenPgpSession
from yubikit.hsmauth import HsmAuthSession
from yubikit.support import read_info, get_name
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin

from dataclasses import asdict
from datetime import datetime
from typing import List, Dict, Any
import platform
import ctypes
import sys
import os


def sys_info():
    info: Dict[str, Any] = {
        "ykman": ykman_version,
        "Python": sys.version,
        "Platform": sys.platform,
        "Arch": platform.machine(),
        "System date": datetime.today().strftime("%Y-%m-%d"),
    }
    if sys.platform == "win32":
        info.update(
            {
                "Running as admin": bool(ctypes.windll.shell32.IsUserAnAdmin()),
                "Windows version": get_windows_version(),
            }
        )
    else:
        info["Running as admin"] = os.getuid() == 0
    return info


def mgmt_info(pid, conn):
    data: List[Any] = []
    try:
        data.append(
            {
                "Raw Info": ManagementSession(conn).backend.read_config(),
            }
        )
    except Exception as e:
        data.append(f"Failed to read device info via Management: {e!r}")

    try:
        info = read_info(conn, pid)
        data.append(
            {
                "DeviceInfo": asdict(info),
                "Name": get_name(info, pid.yubikey_type),
            }
        )
    except Exception as e:
        data.append(f"Failed to read device info: {e!r}")

    return data


def piv_info(conn):
    try:
        piv = PivSession(conn)
        return get_piv_info(piv)
    except Exception as e:
        return f"PIV not accessible {e!r}"


def openpgp_info(conn):
    try:
        openpgp = OpenPgpSession(conn)
        return get_openpgp_info(openpgp)
    except Exception as e:
        return f"OpenPGP not accessible {e!r}"


def oath_info(conn):
    try:
        oath = OathSession(conn)
        return {
            "Oath version": ".".join("%d" % d for d in oath.version),
            "Password protected": oath.locked,
        }
    except Exception as e:
        return f"OATH not accessible {e!r}"


def hsmauth_info(conn):
    try:
        hsmauth = HsmAuthSession(conn)
        return get_hsmauth_info(hsmauth)
    except Exception as e:
        return f"YubiHSM Auth not accessible {e!r}"


def ccid_info():
    try:
        readers = {}
        for reader in list_readers():
            try:
                c = reader.createConnection()
                c.connect()
                c.disconnect()
                result = "Success"
            except Exception as e:
                result = f"<{e.__class__.__name__}>"
            readers[reader.name] = result

        yubikeys: Dict[str, Any] = {}
        for dev in list_ccid_devices():
            try:
                with dev.open_connection(SmartCardConnection) as conn:
                    yubikeys[f"{dev!r}"] = {
                        "Management": mgmt_info(dev.pid, conn),
                        "PIV": piv_info(conn),
                        "OATH": oath_info(conn),
                        "OpenPGP": openpgp_info(conn),
                        "YubiHSM Auth": hsmauth_info(conn),
                    }
            except Exception as e:
                yubikeys[f"{dev!r}"] = f"PC/SC connection failure: {e!r}"

        return {
            "Detected PC/SC readers": readers,
            "Detected YubiKeys over PC/SC": yubikeys,
        }
    except Exception as e:
        return f"PC/SC failure: {e!r}"


def otp_info():
    try:
        yubikeys: Dict[str, Any] = {}
        for dev in list_otp_devices():
            try:
                dev_info = []
                with dev.open_connection(OtpConnection) as conn:
                    dev_info.append(
                        {
                            "Management": mgmt_info(dev.pid, conn),
                        }
                    )
                    otp = YubiOtpSession(conn)
                    try:
                        config = otp.get_config_state()
                        dev_info.append({"OTP": [f"{config}"]})
                    except ValueError as e:
                        dev_info.append({"OTP": f"Couldn't read OTP state: {e!r}"})
                yubikeys[f"{dev!r}"] = dev_info
            except Exception as e:
                yubikeys[f"{dev!r}"] = f"OTP connection failure: {e!r}"

        return {
            "Detected YubiKeys over HID OTP": yubikeys,
        }
    except Exception as e:
        return f"HID OTP backend failure: {e!r}"


def fido_info():
    try:
        yubikeys: Dict[str, Any] = {}
        for dev in list_ctap_devices():
            try:
                dev_info: List[Any] = []
                with dev.open_connection(FidoConnection) as conn:
                    dev_info.append(
                        {
                            "CTAP device version": "%d.%d.%d" % conn.device_version,
                            "CTAPHID protocol version": conn.version,
                            "Capabilities": conn.capabilities,
                            "Management": mgmt_info(dev.pid, conn),
                        }
                    )
                    try:
                        ctap2 = Ctap2(conn)
                        ctap_data: Dict[str, Any] = {"Ctap2Info": asdict(ctap2.info)}
                        if ctap2.info.options.get("clientPin"):
                            client_pin = ClientPin(ctap2)
                            ctap_data["PIN retries"] = client_pin.get_pin_retries()

                            bio_enroll = ctap2.info.options.get("bioEnroll")
                            if bio_enroll:
                                ctap_data[
                                    "Fingerprint retries"
                                ] = client_pin.get_uv_retries()
                            elif bio_enroll is False:
                                ctap_data["Fingerprints"] = "Not configured"
                        else:
                            ctap_data["PIN"] = "Not configured"
                        dev_info.append(ctap_data)
                    except (ValueError, CtapError) as e:
                        dev_info.append(f"Couldn't get CTAP2 info: {e!r}")
                yubikeys[f"{dev!r}"] = dev_info
            except Exception as e:
                yubikeys[f"{dev!r}"] = f"FIDO connection failure: {e!r}"
        return {
            "Detected YubiKeys over HID FIDO": yubikeys,
        }

    except Exception as e:
        return f"HID FIDO backend failure: {e!r}"


def get_diagnostics():
    """Runs diagnostics.

    The result of this can be printed using pretty_print.
    """
    return [
        sys_info(),
        ccid_info(),
        otp_info(),
        fido_info(),
        "End of diagnostics",
    ]
