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

from yubikit.core import ApplicationNotAvailableError
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.smartcard.scp import (
    Scp03KeyParams,
    StaticKeys,
    ScpKid,
    KeyRef,
)
from yubikit.support import get_name, read_info
from yubikit.logging import LOG_LEVEL

from .. import __version__
from ..pcsc import list_devices as list_ccid, list_readers
from ..device import scan_devices, list_all_devices as _list_all_devices
from ..util import (
    get_windows_version,
    parse_private_key,
    parse_certificates,
    InvalidPasswordError,
)
from ..logging import init_logging
from ..diagnostics import get_diagnostics, sys_info
from ..settings import AppData
from .util import (
    YkmanContextObject,
    click_group,
    EnumChoice,
    HexIntParamType,
    CliFail,
    pretty_print,
    click_callback,
    click_prompt,
    find_scp11_params,
    organize_scp11_certificates,
)
from .info import info
from .otp import otp
from .openpgp import openpgp
from .oath import oath
from .piv import piv
from .fido import fido
from .config import config
from .aliases import apply_aliases
from .apdu import apdu
from .script import run_script
from .hsmauth import hsmauth
from .securedomain import securedomain

from cryptography.exceptions import InvalidSignature
from dataclasses import replace
import click
import click.shell_completion
import ctypes
import time
import sys

import logging


logger = logging.getLogger(__name__)


CLICK_CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=999)


WIN_CTAP_RESTRICTED = (
    sys.platform == "win32"
    and not bool(ctypes.windll.shell32.IsUserAnAdmin())
    and get_windows_version() >= (10, 0, 18362)
)


def _scan_changes(state, attempts=10):
    for _ in range(attempts):
        time.sleep(0.25)
        devices, new_state = scan_devices()
        if new_state != state:
            return devices, new_state
    raise TimeoutError("Timed out waiting for state change")


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"YubiKey Manager (ykman) version: {__version__}")
    ctx.exit()


def print_diagnostics(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo("\n".join(pretty_print(get_diagnostics())))
    ctx.exit()


def require_reader(connection_types, reader):
    if SmartCardConnection in connection_types or FidoConnection in connection_types:
        readers = list_ccid(reader)
        if len(readers) == 1:
            dev = readers[0]
            try:
                with dev.open_connection(SmartCardConnection) as conn:
                    info = read_info(conn, dev.pid)
                return dev, info
            except Exception:
                raise CliFail("Failed to connect to YubiKey")
        elif len(readers) > 1:
            raise CliFail("Multiple external readers match name.")
        else:
            raise CliFail("No YubiKey found on external reader.")
    else:
        raise CliFail("Not a CCID command.")


def list_all_devices(*args, **kwargs):
    devices = _list_all_devices(*args, **kwargs)
    with_serial = [(dev, dev_info) for (dev, dev_info) in devices if dev_info.serial]
    if with_serial:
        history = AppData("history")
        cache = history.setdefault("devices", {})
        for dev, dev_info in with_serial:
            if dev_info.serial:
                k = str(dev_info.serial)
                cache[k] = cache.pop(k, None) or _describe_device(dev, dev_info, False)
        # 5, chosen by fair dice roll
        [cache.pop(k) for k in list(cache.keys())[: -max(5, len(with_serial))]]
        history.write()
    return devices


def require_device(connection_types, serial=None):
    # Find all connected devices
    devices, state = scan_devices()
    n_devs = sum(devices.values())
    if serial is None:
        if n_devs == 0:  # The device might not yet be ready, wait a bit
            try:
                devices, state = _scan_changes(state)
                n_devs = sum(devices.values())
            except TimeoutError:
                raise CliFail("No YubiKey detected!")
        if n_devs > 1:
            list_all_devices()  # Update device cache
            raise CliFail(
                "Multiple YubiKeys detected. Use --device SERIAL to specify "
                "which one to use."
            )

        # Only one connected device, check if any needed interfaces are available
        pid = next(iter(devices.keys()))
        supported = [c for c in connection_types if pid.supports_connection(c)]
        if WIN_CTAP_RESTRICTED and supported == [FidoConnection]:
            # FIDO-only command on Windows without Admin won't work.
            raise CliFail("FIDO access on Windows requires running as Administrator.")
        if not supported:
            interfaces = [c.usb_interface for c in connection_types]
            req = ", ".join(t.name or str(t) for t in interfaces)
            raise CliFail(
                f"Command requires one of the following USB interfaces "
                f"to be enabled: '{req}'.\n\n"
                "Use 'ykman config usb' to set the enabled USB interfaces."
            )

        devs = list_all_devices(supported)
        if len(devs) != 1:
            raise CliFail("Failed to connect to YubiKey.")
        return devs[0]
    else:
        for retry in (
            True,
            False,
        ):  # If no match initially, wait a bit for state change.
            devs = list_all_devices(connection_types)
            for dev, dev_info in devs:
                if dev_info.serial == serial:
                    return dev, dev_info
            try:
                if retry:
                    _, state = _scan_changes(state)
            except TimeoutError:
                break

        raise CliFail(
            f"Failed connecting to a YubiKey with serial: {serial}.\n"
            "Make sure the application has the required permissions.",
        )


@click_callback()
def parse_scp_keys(ctx, param, val):
    try:
        keys = [bytes.fromhex(v) for v in val.split(":")]
        if not all(len(k) == 16 for k in keys):
            raise ValueError(
                "SCP keys must be exactly 16 bytes (32 hexadecimal digits) long."
            )
        if len(keys) == 1:
            return StaticKeys(keys[0], keys[0])
        if 2 <= len(keys) <= 3:
            return StaticKeys(*keys)
        raise ValueError(
            "Must provide 1-3 keys for K-ENC and K-MAC, and optionally K-DEK"
        )
    except Exception:
        raise ValueError(val)


@click_group(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option(
    "-d",
    "--device",
    type=int,
    metavar="SERIAL",
    help="specify which YubiKey to interact with by serial number",
    shell_complete=lambda ctx, param, incomplete: [
        click.shell_completion.CompletionItem(
            serial,
            help=description,
        )
        for serial, description in AppData("history").get("devices", {}).items()
        if serial.startswith(incomplete)
    ],
)
@click.option(
    "-r",
    "--reader",
    help="specify a YubiKey by smart card reader name "
    "(can't be used with --device or list)",
    metavar="NAME",
    default=None,
    shell_complete=lambda ctx, param, incomplete: [
        f'"{reader.name}"' for reader in list_readers()
    ],
)
@click.option(
    "-s",
    "--scp",
    default=None,
    type=EnumChoice(ScpKid),
    metavar="KID",
    help="SCP key identifier",
)
@click.option(
    "-V",
    "--scp-kvn",
    default=0,
    type=HexIntParamType(),
    metavar="KVN",
    help="SCP key version",
)
@click.option(
    "-t",
    "--klcc-ca",
    type=click.File("rb"),
    help="specify the CA to use to verify the SCP11 card key (CA-KLCC)",
)
@click.option(
    "-k",
    "--scp03-keys",
    default=None,
    callback=parse_scp_keys,
    metavar="KEYS",
    help="specify keys for secure messaging, K-ENC:K-MAC[:K-DEK]",
)
@click.option(
    "-o",
    "--scp11-oce-key",
    metavar="KID KVN",
    type=HexIntParamType(),
    nargs=2,
    default=(0, 0),
    hidden=True,
    help="specify which key the OCE is using to authenticate",
)
@click.option(
    "-c",
    "--scp11-cred",
    metavar="FILE",
    type=click.File("rb"),
    multiple=True,
    help="specify private key and certificate chain for secure messaging, "
    "can be used multiple times to provide key and certificates in multiple "
    "files (private key, certificates in leaf-last order)",
)
@click.option(
    "-p",
    "--scp11-cred-password",
    metavar="PASSWORD",
    help="specify a password required to access the scp11-cred file",
)
@click.option(
    "-l",
    "--log-level",
    default=None,
    type=EnumChoice(LOG_LEVEL, hidden=[LOG_LEVEL.NOTSET]),
    help="enable logging at given verbosity level",
)
@click.option(
    "--log-file",
    default=None,
    type=str,
    metavar="FILE",
    help="write log to FILE instead of printing to stderr (requires --log-level)",
)
@click.option(
    "--diagnose",
    is_flag=True,
    callback=print_diagnostics,
    expose_value=False,
    is_eager=True,
    help="show diagnostics information useful for troubleshooting",
)
@click.option(
    "-v",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="show version information about the app",
)
@click.option(
    "--full-help",
    is_flag=True,
    expose_value=False,
    help="show --help output, including hidden commands",
)
@click.pass_context
def cli(
    ctx,
    device,
    scp,
    scp_kvn,
    klcc_ca,
    scp03_keys,
    scp11_oce_key,
    scp11_cred,
    scp11_cred_password,
    log_level,
    log_file,
    reader,
):
    """
    Configure your YubiKey via the command line.

    Examples:

    \b
      List connected YubiKeys, only output serial number:
      $ ykman list --serials

    \b
      Show information about YubiKey with serial number 123456:
      $ ykman --device 123456 info
    """
    ctx.obj = YkmanContextObject()

    if log_level:
        init_logging(log_level, log_file=log_file, replace=log_file is None)
        logger.info("\n".join(pretty_print({"System info": sys_info()})))
    elif log_file:
        ctx.fail("--log-file requires specifying --log-level.")

    if reader and device:
        ctx.fail("--reader and --device options can't be combined.")

    use_scp = bool(scp is not None or scp_kvn or scp03_keys or scp11_cred or klcc_ca)

    subcmd = next(c for c in COMMANDS if c.name == ctx.invoked_subcommand)
    # Commands that don't directly act on a key
    if subcmd in (list_keys,):
        if device:
            ctx.fail("--device can't be used with this command.")
        if reader:
            ctx.fail("--reader can't be used with this command.")
        if use_scp:
            ctx.fail("SCP can't be used with this command.")
        return

    # Commands which need a YubiKey to act on
    connections = getattr(
        subcmd, "connections", [SmartCardConnection, FidoConnection, OtpConnection]
    )
    if connections:
        if connections == [FidoConnection] and WIN_CTAP_RESTRICTED:
            # FIDO-only command on Windows without Admin won't work.
            raise CliFail("FIDO access on Windows requires running as Administrator.")

        def resolve():
            items = getattr(resolve, "items", None)
            if not items:
                # We might be connecting over NFC, and thus may require SCP11
                if reader is not None:
                    items = require_reader(connections, reader)
                else:
                    items = require_device(connections, device)
                setattr(resolve, "items", items)
            return items

        ctx.obj.add_resolver("device", lambda: resolve()[0])
        ctx.obj.add_resolver("pid", lambda: resolve()[0].pid)
        ctx.obj.add_resolver("info", lambda: resolve()[1])

        if use_scp:
            if SmartCardConnection not in connections:
                raise CliFail("SCP can only be used with CCID commands")

            if klcc_ca:
                ca = klcc_ca.read()
            else:
                ca = None

            if scp is None:
                if scp03_keys:
                    scp = ScpKid.SCP03
                elif not scp11_cred:
                    scp = ScpKid.SCP11b

            if scp03_keys and scp != ScpKid.SCP03:
                raise CliFail("--scp03-keys can only be used with SCP03")

            if scp == ScpKid.SCP03:
                if klcc_ca:
                    raise CliFail("--klcc-ca can only be used with SCP11")
                if not scp03_keys:
                    scp03_keys = StaticKeys.default()

                def params_f(_):
                    return Scp03KeyParams(
                        ref=KeyRef(ScpKid.SCP03, scp_kvn), keys=scp03_keys
                    )

            elif scp11_cred:
                # SCP11 a/c
                if scp not in (ScpKid.SCP11a, ScpKid.SCP11c, None):
                    raise CliFail("--scp11-cred can only be used with SCP11 a/c")

                creds = [c.read() for c in scp11_cred]
                first = creds.pop(0)
                password = scp11_cred_password.encode() if scp11_cred_password else None

                while True:
                    try:
                        sk_oce_ecka = parse_private_key(first, password)
                        break
                    except InvalidPasswordError:
                        if scp11_cred_password:
                            raise CliFail("Wrong password to decrypt private key")
                        logger.debug("Error parsing key", exc_info=True)
                        password = click_prompt(
                            "Enter password to decrypt SCP11 key",
                            default="",
                            hide_input=True,
                            show_default=False,
                        ).encode()

                if creds:
                    certificates = []
                    for c in creds:
                        certificates.extend(parse_certificates(c, None))
                else:
                    certificates = parse_certificates(first, password)
                    # If the bundle contains the CA we strip it out
                    _, inter, leaf = organize_scp11_certificates(certificates)
                    # Send the KA-KLOC and OCE certificates
                    certificates = list(inter) + [leaf]

                def params_f(conn):
                    if not scp:
                        # Check for SCP11a key, then SCP11c
                        try:
                            params = find_scp11_params(conn, ScpKid.SCP11a, scp_kvn, ca)
                        except (ValueError, InvalidSignature) as e:
                            try:
                                params = find_scp11_params(
                                    conn, ScpKid.SCP11c, scp_kvn, ca
                                )
                            except (ValueError, InvalidSignature):
                                raise e
                    else:
                        params = find_scp11_params(conn, scp, scp_kvn, ca)
                    return replace(
                        params,
                        oce_ref=KeyRef(*scp11_oce_key),
                        sk_oce_ecka=sk_oce_ecka,
                        certificates=certificates,
                    )

            else:
                # SCP11b
                if scp not in (ScpKid.SCP11b, None):
                    raise CliFail(f"{scp.name} requires --scp11-cred")
                if any(scp11_oce_key):
                    raise CliFail("SCP11b cannot be used with --scp11-oce-key")

                def params_f(conn):
                    return find_scp11_params(conn, ScpKid.SCP11b, scp_kvn, ca)

            connections = [SmartCardConnection]

            # TODO: Use these
            ctx.obj.add_resolver("scp", lambda: params_f)


@cli.command("list")
@click.option(
    "-s",
    "--serials",
    is_flag=True,
    help="output only serial numbers, one per line "
    "(devices without serial will be omitted)",
)
@click.option("-r", "--readers", is_flag=True, help="list available smart card readers")
@click.pass_context
def list_keys(ctx, serials, readers):
    """
    List connected YubiKeys.
    """

    if readers:
        for reader in list_readers():
            click.echo(reader.name)
        ctx.exit()

    # List all attached devices
    pids = set()
    for dev, dev_info in list_all_devices():
        if serials:
            if dev_info.serial:
                click.echo(dev_info.serial)
        else:
            click.echo(
                _describe_device(dev, dev_info)
                + (f" Serial: {dev_info.serial}" if dev_info.serial else "")
            )
        pids.add(dev.pid)

    # Look for FIDO devices that we can't access
    if not serials:
        devs, _ = scan_devices()
        for pid, count in devs.items():
            if pid not in pids:
                for _ in range(count):
                    name = pid.yubikey_type.value
                    mode = pid.name.split("_", 1)[1].replace("_", "+")
                    click.echo(f"{name} [{mode}] <access denied>")


def _describe_device(dev, dev_info, include_mode=True):
    if dev.pid is None:  # Devices from list_all_devices should always have PID.
        raise AssertionError("PID is None")
    name = get_name(dev_info, dev.pid.yubikey_type)
    version = dev_info.version or "unknown"
    description = f"{name} ({version})"
    if include_mode:
        mode = dev.pid.name.split("_", 1)[1].replace("_", "+")
        description += f" [{mode}]"
    return description


COMMANDS = (
    list_keys,
    info,
    otp,
    openpgp,
    oath,
    piv,
    fido,
    config,
    apdu,
    run_script,
    hsmauth,
    securedomain,
)


for cmd in COMMANDS:
    cli.add_command(cmd)


class _DefaultFormatter(logging.Formatter):
    def __init__(self, show_trace=False):
        self.show_trace = show_trace

    def format(self, record):
        message = f"{record.levelname}: {record.getMessage()}"
        if self.show_trace and record.exc_info:
            message += self.formatException(record.exc_info)
        return message


def main():
    # Set up default logging
    handler = logging.StreamHandler()
    handler.setLevel(logging.WARNING)
    formatter = _DefaultFormatter()
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)

    sys.argv = apply_aliases(sys.argv)
    try:
        # --full-help triggers --help, hidden commands will already have read it by now.
        sys.argv[sys.argv.index("--full-help")] = "--help"
    except ValueError:
        pass  # No --full-help

    try:
        cli(obj={})
    except Exception as e:
        status = 1
        if isinstance(e, CliFail):
            status = e.status
            msg = e.args[0]
        elif isinstance(e, ApplicationNotAvailableError):
            msg = (
                "The functionality required for this command is not enabled or not "
                "available on this YubiKey."
            )
        elif isinstance(e, ValueError):
            msg = f"{e}"
        else:
            msg = "An unexpected error has occurred"
            formatter.show_trace = True
        logger.exception(msg)
        logging.shutdown()
        sys.exit(status)


if __name__ == "__main__":
    main()
