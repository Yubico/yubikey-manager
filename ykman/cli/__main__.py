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

from __future__ import absolute_import, print_function

from yubikit.core import TRANSPORT

import ykman.logging_setup
import smartcard.pcsc.PCSCExceptions

from .. import __version__
from ..hid import list_devices as list_hid
from ..scard import list_devices as list_ccid, list_readers
from ..util import Cve201715361VulnerableError
from ..device import read_info, get_name
from .util import UpperCaseChoice, YkmanContextObject
from .info import info
from .mode import mode
from .otp import otp
from .opgp import openpgp
from .oath import oath
from .piv import piv
from .fido import fido
from .config import config
import click
import logging
import sys


logger = logging.getLogger(__name__)


CLICK_CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=999)


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo("YubiKey Manager (ykman) version: {}".format(__version__))
    ctx.exit()


def _disabled_transport(ctx, transports, cmd_name):
    req = ", ".join((t.name for t in TRANSPORT if t & transports))
    click.echo(
        "Command '{}' requires one of the following USB interfaces "
        "to be enabled: '{}'.".format(cmd_name, req)
    )
    ctx.fail("Use 'ykman mode' to set the enabled USB interfaces.")


def _run_cmd_for_serial(ctx, cmd, transports, serial):
    if TRANSPORT.has(transports, TRANSPORT.CCID):
        for dev in list_ccid():
            conn = dev.open_iso7816_connection()
            info = read_info(dev.pid, conn)
            if info.serial == serial:
                return dev, conn, info
            else:
                conn.close()
    if TRANSPORT.has(transports, TRANSPORT.OTP):
        for dev in list_hid():
            if dev.has_otp:
                conn = dev.open_otp_connection()
                info = read_info(dev.pid, conn)
                if info.serial == serial:
                    return dev, conn, info
                else:
                    conn.close()
    if TRANSPORT.has(transports, TRANSPORT.FIDO):
        for dev in list_hid():
            if dev.has_ctap:
                conn = dev.open_ctap_device()
                info = read_info(dev.pid, conn)
                if info.serial == serial:
                    return dev, conn, info
                else:
                    conn.close()
    ctx.fail(
        "Failed connecting to a YubiKey with serial: {}. "
        "Make sure the application has the required "
        "permissions.".format(serial)
    )

    # TODO: Check other transports for serial, and if device supports transport.
    # Serial not found, see if it's among other transports in USB enabled:


def _run_cmd_for_single(ctx, cmd, transports, reader=None):
    if reader:
        if TRANSPORT.has(transports, TRANSPORT.CCID) or cmd == fido.name:
            readers = list_ccid(reader)
            if len(readers) == 1:
                dev = readers[0]
                if cmd == fido.name:
                    conn = dev.open_ctap_device()
                else:
                    conn = dev.open_iso7816_connection()
                info = read_info(dev.pid, conn)
                return dev, conn, info
            elif len(readers) > 1:
                ctx.fail("Multiple YubiKeys on external readers detected.")
            else:
                ctx.fail("No YubiKey found on external reader.")
        else:
            ctx.fail("Not a CCID command.")

    dev = [None, None, None, None]
    for hid in list_hid():
        if not dev[0]:
            dev[0] = hid.pid
        elif dev[0] != hid.pid:
            ctx.fail("Multiple devices found")
        if hid.has_otp:
            if dev[1]:
                ctx.fail("Multiple devices found")
            dev[1] = hid
        if hid.has_ctap:
            if dev[2]:
                ctx.fail("Multiple devices found")
            dev[2] = hid
    for ccid in list_ccid():
        if not dev[0]:
            dev[0] = ccid.pid
        elif dev[0] != ccid.pid:
            ctx.fail("Multiple devices found")
        if dev[3]:
            ctx.fail("Multiple devices found")
        dev[3] = ccid

    if dev[0] is None:
        ctx.fail("No YubiKey detected!")

    if dev[3]:
        dev = dev[3]
        conn = dev.open_iso7816_connection()
    elif dev[1]:
        dev = dev[1]
        conn = dev.open_otp_connection()
    elif dev[2]:
        dev = dev[2]
        conn = dev.open_ctap_device()
    else:
        ctx.fail(
            "Multiple YubiKeys detected. Use --device SERIAL to specify "
            "which one to use."
        )
        ctx.fail(
            "Failed connecting to {} {}. "
            "Make sure the application has the "
            "required permissions.".format(
                dev.pid.get_type().value, TRANSPORT.split(dev.pid.get_transports())
            )
        )
        # TODO: _disabled_transport(ctx, transports, cmd)

    info = read_info(dev.pid, conn)
    return dev, conn, info


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option(
    "-v",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@click.option("-d", "--device", type=int, metavar="SERIAL")
@click.option(
    "-l",
    "--log-level",
    default=None,
    type=UpperCaseChoice(ykman.logging_setup.LOG_LEVEL_NAMES),
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
    "-r",
    "--reader",
    help="Use an external smart card reader. Conflicts with --device and " "list.",
    metavar="NAME",
    default=None,
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
    if subcmd == list_keys:
        if reader:
            ctx.fail("--reader and list command can't be combined.")
        return

    transports = getattr(subcmd, "transports", TRANSPORT.usb_transports())
    if transports:

        def resolve():
            if not getattr(resolve, "items", None):
                if device is not None:
                    resolve.items = _run_cmd_for_serial(
                        ctx, subcmd.name, transports, device
                    )
                else:
                    resolve.items = _run_cmd_for_single(
                        ctx, subcmd.name, transports, reader
                    )
                ctx.call_on_close(resolve.items[1].close)
            return resolve.items

        ctx.obj.add_resolver("dev", lambda: resolve()[0])
        ctx.obj.add_resolver("conn", lambda: resolve()[1])
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

    def _print_device(dev, info):
        if serials:
            if info.serial:
                click.echo(info.serial)
        else:
            click.echo(
                "{} ({}) [{}]{}".format(
                    get_name(dev.pid.get_type(), info),
                    "%d.%d.%d" % info.version if info.version else "unknown",
                    dev.pid.name.split("_", 1)[1].replace("_", "+"),
                    " Serial: {}".format(info.serial) if info.serial else "",
                )
            )

    if readers:
        for reader in list_readers():
            click.echo(reader.name)
        ctx.exit()

    # List all attached devices
    handled_pids = set()
    hid_devs = list_hid()
    pids = {}

    def handle(dev, get_connection):
        if dev.pid not in handled_pids and pids.get(dev.pid, True):
            try:
                with get_connection(dev) as conn:
                    info = read_info(dev.pid, conn)
                pids[dev.pid] = True
                _print_device(dev, info)
            except Exception as e:
                pids[dev.pid] = False
                logger.error("Failed opening device", exc_info=e)

    # Handle OTP devices
    for dev in filter(lambda d: d.has_otp, hid_devs):
        handle(dev, lambda d: d.open_otp_connection())
    handled_pids.update({pid for pid, handled in pids.items() if handled})

    # Handle CCID devices
    try:
        for dev in list_ccid():
            handle(dev, lambda d: d.open_iso7816_connection())
        handled_pids.update({pid for pid, handled in pids.items() if handled})
    except smartcard.pcsc.PCSCExceptions.EstablishContextException as e:
        logger.error("Failed to list devices", exc_info=e)
        ctx.fail("Failed to establish CCID context. Is the pcscd service running?")

    # Handle FIDO devices
    for dev in filter(lambda d: d.has_ctap, hid_devs):
        handle(dev, lambda d: d.open_ctap_device())
    handled_pids.update({pid for pid, handled in pids.items() if handled})


COMMANDS = (list_keys, info, mode, otp, openpgp, oath, piv, fido, config)


for cmd in COMMANDS:
    cli.add_command(cmd)


def main():
    try:
        cli(obj={})
    except ValueError as e:
        logger.error("Error", exc_info=e)
        click.echo("Error: " + str(e))
        return 1

    except Cve201715361VulnerableError as err:
        logger.error("Error", exc_info=err)
        click.echo("Error: " + str(err))
        return 2


if __name__ == "__main__":
    sys.exit(main())
