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

from ykman.hid import list_devices as list_hid
from ykman.scard import list_devices as list_ccid, list_readers
from ykman.yubikit.core import TRANSPORT

import ykman.logging_setup
import smartcard.pcsc.PCSCExceptions

from ykman import __version__
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
import usb.core
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
                return conn, info
            else:
                conn.close()
    elif TRANSPORT.has(transports, TRANSPORT.OTP):
        for dev in list_hid():
            if dev.has_otp:
                conn = dev.open_otp_connection()
                info = read_info(dev.pid, conn)
                if info.serial == serial:
                    return conn, info
                else:
                    conn.close()
    elif TRANSPORT.has(transports, TRANSPORT.FIDO):
        for dev in list_hid():
            if dev.has_ctap:
                conn = dev.open_ctap_device()
                info = read_info(dev.pid, conn)
                if info.serial == serial:
                    return conn, info
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
                # TODO: return YubiKey(Descriptor.from_driver(readers[0]), readers[0])
                pass
            elif len(readers) > 1:
                ctx.fail("Multiple YubiKeys on external readers detected.")
            else:
                ctx.fail("No YubiKey found on external reader.")
        else:
            ctx.fail("Not a CCID command.")
    try:
        # TODO: descriptors = get_descriptors()
        descriptors = None
        pass
    except usb.core.NoBackendError:
        ctx.fail("No PyUSB backend detected!")
    n_keys = len(descriptors)
    if n_keys == 0:
        ctx.fail("No YubiKey detected!")
    if n_keys > 1:
        ctx.fail(
            "Multiple YubiKeys detected. Use --device SERIAL to specify "
            "which one to use."
        )
    descriptor = descriptors[0]
    if descriptor.mode.transports & transports:
        try:
            return descriptor.open_device(transports)
        except Exception:
            ctx.fail(
                "Failed connecting to {} [{}]. "
                "Make sure the application has the "
                "required permissions.".format(descriptor.name, descriptor.mode)
            )
    else:
        _disabled_transport(ctx, transports, cmd)


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
        conn, info = None, None

        def resolve_device():
            if device is not None:
                conn, info = _run_cmd_for_serial(ctx, subcmd.name, transports, device)
            else:
                conn, info = _run_cmd_for_single(ctx, subcmd.name, transports, reader)
            ctx.call_on_close(conn.close)
            return conn, info

        ctx.obj.add_resolver("conn", lambda: conn or resolve_device()[0])
        ctx.obj.add_resolver("info", lambda: info or resolve_device()[1])


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

    def _print_device(dev, name, serial=None):
        if serials:
            if serial:
                click.echo(serial)
        else:
            click.echo(
                "{} [{}]{}".format(
                    name,
                    dev.pid.name.split("_", 1)[1].replace("_", "+"),
                    " Serial: {}".format(serial) if serial else "",
                )
            )

    if readers:
        for reader in list_readers():
            click.echo(reader.name)
        ctx.exit()

    handled_serials = set()

    for dev in list_hid():
        try:
            if dev.has_otp:
                with dev.open_otp_connection() as conn:
                    info = read_info(dev.pid, conn)
            elif dev.has_ctap:
                with dev.open_ctap_device() as conn:
                    info = read_info(dev.pid, conn)
            name = get_name(dev.pid, info)
            if info.serial:
                if info.serial not in handled_serials:
                    handled_serials.add(info.serial)
                    _print_device(dev, "%s: %r" % (name, info.version), info.serial)
            else:
                _print_device(dev, "%s: %r" % (name, info.version))
        except Exception as e:
            print(e)
    try:
        for dev in list_ccid():
            try:
                with dev.open_iso7816_connection() as conn:
                    info = read_info(dev.pid, conn)
            except smartcard.Exceptions.NoCardException:
                logger.info("Failed to connect to device, no card inserted")
                continue
            name = get_name(dev.pid, info)
            if info.serial:
                if info.serial not in handled_serials:
                    handled_serials.add(info.serial)
                    _print_device(dev, "%s: %r" % (name, info.version), info.serial)
            else:
                _print_device(dev, "%s: %r" % (name, info.version))
    except smartcard.pcsc.PCSCExceptions.EstablishContextException as e:
        logger.error("Failed to list devices", exc_info=e)
        ctx.fail("Failed to establish CCID context. Is the pcscd service running?")


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
