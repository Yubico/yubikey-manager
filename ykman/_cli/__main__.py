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
from yubikit.support import get_name, read_info
from yubikit.logging import LOG_LEVEL

from .. import __version__
from ..pcsc import list_devices as list_ccid, list_readers
from ..device import scan_devices, list_all_devices as _list_all_devices
from ..util import get_windows_version
from ..logging import init_logging
from ..diagnostics import get_diagnostics, sys_info
from ..settings import AppData
from .util import YkmanContextObject, click_group, EnumChoice, CliFail, pretty_print
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
def cli(ctx, device, log_level, log_file, reader):
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
        init_logging(log_level, log_file=log_file)
        logger.info("\n".join(pretty_print({"System info": sys_info()})))
    elif log_file:
        ctx.fail("--log-file requires specifying --log-level.")

    if reader and device:
        ctx.fail("--reader and --device options can't be combined.")

    subcmd = next(c for c in COMMANDS if c.name == ctx.invoked_subcommand)
    # Commands that don't directly act on a key
    if subcmd in (list_keys,):
        if device:
            ctx.fail("--device can't be used with this command.")
        if reader:
            ctx.fail("--reader can't be used with this command.")
        return

    # Commands which need a YubiKey to act on
    connections = getattr(
        subcmd, "connections", [SmartCardConnection, FidoConnection, OtpConnection]
    )
    if connections:

        def resolve():
            if connections == [FidoConnection] and WIN_CTAP_RESTRICTED:
                # FIDO-only command on Windows without Admin won't work.
                raise CliFail(
                    "FIDO access on Windows requires running as Administrator."
                )

            items = getattr(resolve, "items", None)
            if not items:
                if reader is not None:
                    items = require_reader(connections, reader)
                else:
                    items = require_device(connections, device)
                setattr(resolve, "items", items)
            return items

        ctx.obj.add_resolver("device", lambda: resolve()[0])
        ctx.obj.add_resolver("pid", lambda: resolve()[0].pid)
        ctx.obj.add_resolver("info", lambda: resolve()[1])


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
        sys.exit(status)


if __name__ == "__main__":
    main()
