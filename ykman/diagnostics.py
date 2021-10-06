from . import __version__ as ykman_version
from .logging_setup import log_sys_info
from .pcsc import list_readers, list_devices as list_ccid_devices
from .hid import list_otp_devices, list_ctap_devices
from .device import read_info, get_name
from .piv import get_piv_info
from .openpgp import OpenPgpController, get_openpgp_info

from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.management import ManagementSession
from yubikit.yubiotp import YubiOtpSession
from yubikit.piv import PivSession
from yubikit.oath import OathSession
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin


def mgmt_info(pid, conn):
    data = {}
    try:
        raw_info = ManagementSession(conn).backend.read_config()
        data["RawInfo"] = raw_info.hex()
    except Exception as e:
        data["Failed to read device info via Management"] = f"{e!r}"
    try:
        info = read_info(pid, conn)
        data["Info"] = f"{info}"
        name = get_name(info, pid.get_type())
        data["Device name"] = f"{name}"
    except Exception as e:
        data["Failed to read device info"] = f"{e!r}"
    return data


def piv_info(conn):
    try:
        piv = PivSession(conn)
        return "\n" + get_piv_info(piv)
    except Exception as e:
        return {"PIV not accessible": f"{e!r}"}


def openpgp_info(conn):
    try:
        openpgp = OpenPgpController(conn)
        return "\n" + get_openpgp_info(openpgp)
    except Exception as e:
        return {"OpenPGP not accessible": f"{e!r}"}


def oath_info(conn):
    try:
        oath = OathSession(conn)
        return {
            "OATH version": f"{'.'.join('%d' % d for d in oath.version)}",
            "Password protected": oath.locked,
        }
    except Exception as e:
        return {"OATH not accessible": f"{e!r}"}


def ccid_info():
    data = {}
    try:
        reader_data = []
        readers = list_readers()
        for reader in readers:
            try:
                c = reader.createConnection()
                c.connect()
                c.disconnect()
                result = "Success"
            except Exception as e:
                result = e.__class__.__name__
            reader_data.append({reader.name: f"Connect: {result}"})
        data["Detected PC/SC readers"] = reader_data
    except Exception as e:
        return {"PC/SC failure": f"{e!r}"}

    try:
        devs = {}
        for dev in list_ccid_devices():
            try:
                with dev.open_connection(SmartCardConnection) as conn:
                    result = {
                        "Management": mgmt_info(dev.pid, conn),
                        "PIV": piv_info(conn),
                        "OATH": oath_info(conn),
                        "OpenPGP": openpgp_info(conn),
                    }
            except Exception as e:
                result = {"PC/SC connection failure": f"{e!r}"}
            devs[f"{dev!r}"] = result
        data["Detected YubiKeys over PC/SC"] = devs
    except Exception as e:
        return {"PC/SC failure": f"{e!r}"}

    return data


def otp_info():
    data = {}
    try:
        for dev in list_otp_devices():
            try:
                result = {}
                with dev.open_connection(OtpConnection) as conn:
                    result["Management"] = mgmt_info(dev.pid, conn)
                    otp = YubiOtpSession(conn)
                    try:
                        config = otp.get_config_state()
                        result["OTP"] = config
                    except ValueError as e:
                        result["Couldn't read OTP state"] = f"{e!r}"
            except Exception as e:
                result = {"OTP connection failure": f"{e!r}"}
            data[f"{dev!r}"] = result
    except Exception as e:
        data["HID OTP backend failure"] = f"{e!r}"
    return data


def fido_info():
    data = {}
    try:
        for dev in list_ctap_devices():
            try:
                result = {}
                with dev.open_connection(FidoConnection) as conn:
                    result["CTAP device version"] = "%d.%d.%d" % conn.device_version
                    result["CTAPHID protocol version"] = f"{conn.version}"
                    result["Capabilities"] = "%d" % conn.capabilities
                    result["Management"] = mgmt_info(dev.pid, conn)
                    try:
                        ctap2 = Ctap2(conn)
                        result["Ctap2Info"] = f"{ctap2.info.data!r}"
                        if ctap2.info.options.get("clientPin"):
                            client_pin = ClientPin(ctap2)
                            result["PIN retries"] = f"{client_pin.get_pin_retries()}"
                            bio_enroll = ctap2.info.options.get("bioEnroll")
                            if bio_enroll:
                                result[
                                    "Fingerprint retries"
                                ] = f"{client_pin.get_uv_retries()}"
                            elif bio_enroll is False:
                                result["Fingerprints"] = "Not configured"
                        else:
                            result["PIN"] = "Not configured"

                    except (ValueError, CtapError) as e:
                        result["Couldn't get info"] = f"{e!r}"
            except Exception as e:
                result = {"FIDO connection failure": f"{e!r}"}
            data[f"{dev!r}"] = result
    except Exception as e:
        data["HID FIDO backend failure"] = f"{e!r}"
    return data


def get_diagnostics():
    data = {"ykman": f"{ykman_version}"}
    sysinfo = []
    log_sys_info(sysinfo.append)
    data["System"] = "\n" + "\n".join(f"    {ln}" for ln in sysinfo)

    data.update(ccid_info())
    data["Detected YubiKeys over HID OTP"] = otp_info()
    data["Detected YubiKeys over HID FIDO"] = fido_info()

    return data


def get_diagnostics_text():
    lines = []

    def _pretty_print(data, level=0):
        for key, value in data.items():
            line = level * "   " + key + ":"
            if isinstance(value, dict):
                lines.append(line)
                _pretty_print(value, level + 1)
            elif isinstance(value, list):
                lines.append(line)
                for item in value:
                    _pretty_print(item, level + 1)
            else:
                line += f" {value}"
                lines.append(line)

    _pretty_print(get_diagnostics())
    lines.append("End of diagnostics")

    return "\n".join(lines)
