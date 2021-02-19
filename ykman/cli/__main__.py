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
from yubikit.management import USB_INTERFACE

import ykman.logging_setup

from .. import __version__
from ..pcsc import list_devices as list_ccid, list_readers
from ..device import (
    read_info,
    get_name,
    list_all_devices,
    scan_devices,
    connect_to_device,
)
from ..util import get_windows_version
from ..diagnostics import get_diagnostics
from .util import YkmanContextObject, ykman_group, cli_fail
from .info import info
from .otp import otp
from .openpgp import openpgp
from .oath import oath
from .piv import piv
from .fido import fido
from .config import config
from .aliases import apply_aliases
from .apdu import apdu
import click
import ctypes
import time
import sys
import logging


logger = logging.getLogger(__name__)


CLICK_CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=999)


USB_INTERFACE_MAPPING = {
    SmartCardConnection: USB_INTERFACE.CCID,
    OtpConnection: USB_INTERFACE.OTP,
    FidoConnection: USB_INTERFACE.FIDO,
}


WIN_CTAP_RESTRICTED = (
    sys.platform == "win32"
    and not bool(ctypes.windll.shell32.IsUserAnAdmin())
    and get_windows_version() >= (10, 0, 18362)
)


def retrying_connect(serial, connections, attempts=10, state=None):
    while True:
        try:
            return connect_to_device(serial, connections)
        except Exception as e:
            logger.error("Failed opening connection", exc_info=e)
            while attempts:
                attempts -= 1
                _, new_state = scan_devices()
                if new_state != state:
                    state = new_state
                    logger.debug("State changed, re-try connect...")
                    break
                logger.debug("Sleep...")
                time.sleep(0.5)
            else:
                raise


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"YubiKey Manager (ykman) version: {__version__}")
    ctx.exit()


def print_diagnostics(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(get_diagnostics())
    ctx.exit()


def _disabled_interface(connections, cmd_name):
    interfaces = [USB_INTERFACE_MAPPING[c] for c in connections]
    req = ", ".join((t.name for t in interfaces))
    cli_fail(
        f"Command '{cmd_name}' requires one of the following USB interfaces "
        f"to be enabled: '{req}'.\n\n"
        "Use 'ykman config usb' to set the enabled USB interfaces."
    )


def _run_cmd_for_serial(cmd, connections, serial):
    try:
        return retrying_connect(serial, connections)
    except ValueError:
        try:
            # Serial not found, see if it's among other interfaces in USB enabled:
            conn = connect_to_device(serial)[0]
            conn.close()
            _disabled_interface(connections, cmd)
        except ValueError:
            cli_fail(
                f"Failed connecting to a YubiKey with serial: {serial}.\n"
                "Make sure the application has the required permissions."
            )


def _run_cmd_for_single(ctx, cmd, connections, reader_name=None):
    # Use a specific CCID reader
    if reader_name:
        if SmartCardConnection in connections or cmd in (fido.name, otp.name):
            readers = list_ccid(reader_name)
            if len(readers) == 1:
                dev = readers[0]
                try:
                    if cmd == fido.name:
                        conn = dev.open_connection(FidoConnection)
                    else:
                        conn = dev.open_connection(SmartCardConnection)
                    info = read_info(dev.pid, conn)
                    return conn, dev, info
                except Exception as e:
                    logger.error("Failure connecting to card", exc_info=e)
                    cli_fail(f"Failed to connect: {e}")
            elif len(readers) > 1:
                cli_fail("Multiple YubiKeys on external readers detected.")
            else:
                cli_fail("No YubiKey found on external reader.")
        else:
            ctx.fail("Not a CCID command.")

    # Find all connected devices
    devices, state = scan_devices()
    n_devs = sum(devices.values())

    if n_devs == 0:
        cli_fail("No YubiKey detected!")
    if n_devs > 1:
        cli_fail(
            "Multiple YubiKeys detected. Use --device SERIAL to specify "
            "which one to use."
        )

    # Only one connected device, check if any needed interfaces are available
    pid = next(iter(devices.keys()))
    for c in connections:
        if USB_INTERFACE_MAPPING[c] & pid.get_interfaces():
            if WIN_CTAP_RESTRICTED and c == FidoConnection:
                # FIDO-only command on Windows without Admin won't work.
                cli_fail("FIDO access on Windows requires running as Administrator.")
            return retrying_connect(None, connections, state=state)
    _disabled_interface(connections, cmd)


@ykman_group(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option(
    "-d",
    "--device",
    type=int,
    metavar="SERIAL",
    help="Specify which YubiKey to interact with by serial number.",
)
@click.option(
    "-r",
    "--reader",
    help="Use an external smart card reader. Conflicts with --device and list.",
    metavar="NAME",
    default=None,
)
@click.option(
    "-l",
    "--log-level",
    default=None,
    type=click.Choice(ykman.logging_setup.LOG_LEVEL_NAMES, case_sensitive=False),
    help="Enable logging at given verbosity level.",
)
@click.option(
    "--log-file",
    default=None,
    type=str,
    metavar="FILE",
    help="Write logs to the given FILE instead of standard error; "
    "ignored unless --log-level is also set.",
)
@click.option(
    "--diagnose",
    is_flag=True,
    callback=print_diagnostics,
    expose_value=False,
    is_eager=True,
    help="Show diagnostics information useful for troubleshooting.",
)
@click.option(
    "-v",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Show version information about the app",
)
@click.option(
    "--full-help",
    is_flag=True,
    expose_value=False,
    help="Show --help, including hidden commands, and exit.",
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
      Show information about YubiKey with serial number 0123456:
      $ ykman --device 0123456 info
    """
    ctx.obj = YkmanContextObject()

    if log_level:
        ykman.logging_setup.setup(log_level, log_file=log_file)

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
        if connections == [FidoConnection] and WIN_CTAP_RESTRICTED:
            # FIDO-only command on Windows without Admin won't work.
            cli_fail("FIDO access on Windows requires running as Administrator.")

        def resolve():
            if not getattr(resolve, "items", None):
                if device is not None:
                    resolve.items = _run_cmd_for_serial(
                        subcmd.name, connections, device
                    )
                else:
                    resolve.items = _run_cmd_for_single(
                        ctx, subcmd.name, connections, reader
                    )
                ctx.call_on_close(resolve.items[0].close)
            return resolve.items

        ctx.obj.add_resolver("conn", lambda: resolve()[0])
        ctx.obj.add_resolver("pid", lambda: resolve()[1].pid)
        ctx.obj.add_resolver("info", lambda: resolve()[2])


@cli.command("list")
@click.option(
    "-s",
    "--serials",
    is_flag=True,
    help="Output only serial "
    "numbers, one per line (devices without serial will be omitted).",
)
@click.option(
    "-r", "--readers", is_flag=True, help="List available smart card readers."
)
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
            name = get_name(dev_info, dev.pid.get_type())
            version = "%d.%d.%d" % dev_info.version if dev_info.version else "unknown"
            mode = dev.pid.name.split("_", 1)[1].replace("_", "+")
            click.echo(
                f"{name} ({version}) [{mode}]"
                + (f" Serial: {dev_info.serial}" if dev_info.serial else "")
            )
        pids.add(dev.pid)

    # Look for FIDO devices that we can't access
    if not serials:
        devs, _ = scan_devices()
        for pid, count in devs.items():
            if pid not in pids:
                for _ in range(count):
                    name = pid.get_type().value
                    mode = pid.name.split("_", 1)[1].replace("_", "+")
                    click.echo(f"{name} [{mode}] <access denied>")


COMMANDS = (list_keys, info, otp, openpgp, oath, piv, fido, config, apdu)


for cmd in COMMANDS:
    cli.add_command(cmd)


def main():
    sys.argv = apply_aliases(sys.argv)
    try:
        # --full-help triggers --help, hidden commands will already have read it by now.
        sys.argv[sys.argv.index("--full-help")] = "--help"
    except ValueError:
        pass  # No --full-help

    try:
        cli(obj={})
    except ApplicationNotAvailableError as e:
        logger.error("Error", exc_info=e)
        cli_fail(
            "The functionality required for this command is not enabled or not "
            "available on this YubiKey."
        )
    except ValueError as e:
        logger.error("Error", exc_info=e)
        cli_fail(str(e))


if __name__ == "__main__":
    main()
