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

from __future__ import absolute_import

from yubikit.core import TRANSPORT, INTERFACE, APPLICATION, YUBIKEY
from yubikit.management import ManagementSession, Mode

from .util import click_force_option
import logging
import re
import click


logger = logging.getLogger(__name__)


def _parse_transport_string(transport):
    for t in TRANSPORT:
        if t.name.startswith(transport):
            return t
    raise ValueError()


def _parse_mode_string(ctx, param, mode):
    if mode is None:
        return None
    try:
        mode_int = int(mode)
        return Mode.from_code(mode_int)
    except IndexError:
        ctx.fail("Invalid mode: {}".format(mode_int))
    except ValueError:
        pass  # Not a numeric mode, parse string

    try:
        transports = TRANSPORT(0)
        if mode[0] in ["+", "-"]:
            info = ctx.obj["info"]
            usb_enabled = info.config.enabled_applications[INTERFACE.USB]
            my_mode = _mode_from_usb_enabled(usb_enabled)
            transports |= my_mode.transports
            for mod in re.findall(r"[+-][A-Z]+", mode.upper()):
                transport = _parse_transport_string(mod[1:])
                if mod.startswith("+"):
                    transports |= transport
                else:
                    transports ^= transport
        else:
            for t in filter(None, re.split(r"[+]+", mode.upper())):
                transports |= _parse_transport_string(t)
    except ValueError:
        ctx.fail("Invalid mode string: {}".format(mode))

    return Mode(transports)


def _mode_from_usb_enabled(usb_enabled):
    transports = 0
    if APPLICATION.OTP & usb_enabled:
        transports |= TRANSPORT.OTP
    if (APPLICATION.U2F | APPLICATION.FIDO2) & usb_enabled:
        transports |= TRANSPORT.FIDO
    if (APPLICATION.OPGP | APPLICATION.PIV | APPLICATION.OATH) & usb_enabled:
        transports |= TRANSPORT.CCID
    return Mode(transports)


@click.command()
@click.argument("mode", required=False, callback=_parse_mode_string)
@click.option(
    "--touch-eject",
    is_flag=True,
    help="When set, the button "
    "toggles the state of the smartcard between ejected and inserted "
    "(CCID mode only).",
)
@click.option(
    "--autoeject-timeout",
    required=False,
    type=int,
    default=0,
    metavar="SECONDS",
    help="When set, the smartcard will automatically eject after the "
    "given time. Implies --touch-eject (CCID mode only).",
)
@click.option(
    "--chalresp-timeout",
    required=False,
    type=int,
    default=0,
    metavar="SECONDS",
    help="Sets the timeout when waiting for touch for challenge " "response.",
)
@click_force_option
@click.pass_context
def mode(ctx, mode, touch_eject, autoeject_timeout, chalresp_timeout, force):
    """
    Manage connection modes (USB Interfaces).

    Get the current connection mode of the YubiKey, or set it to MODE.

    MODE can be a string, such as "OTP+FIDO+CCID", or a shortened form: "o+f+c".
    It can also be a mode number.

    Examples:

    \b
      Set the OTP and FIDO mode:
      $ ykman mode OTP+FIDO

    \b
      Set the CCID only mode and use touch to eject the smart card:
      $ ykman mode CCID --touch-eject
    """
    info = ctx.obj["info"]
    mgmt = ManagementSession(ctx.obj["conn"])
    usb_enabled = info.config.enabled_applications[INTERFACE.USB]
    my_mode = _mode_from_usb_enabled(usb_enabled)
    usb_supported = info.supported_applications[INTERFACE.USB]
    transports_supported = _mode_from_usb_enabled(usb_supported).transports
    pid = ctx.obj["pid"]
    if pid:
        key_type = pid.get_type()
    else:
        key_type = None

    if autoeject_timeout:
        touch_eject = True
    autoeject = autoeject_timeout if touch_eject else 0

    if mode is not None:
        if mode.transports != TRANSPORT.CCID:
            if touch_eject:
                ctx.fail(
                    "--touch-eject can only be used when setting" " CCID-only mode"
                )

        if not force:
            if mode == my_mode:
                click.echo("Mode is already {}, nothing to do...".format(mode))
                ctx.exit()
            elif key_type in (YUBIKEY.YKS, YUBIKEY.YKP):
                click.echo(
                    "Mode switching is not supported on this YubiKey!".format(mode)
                )
                ctx.fail("Use --force to attempt to set it anyway.")
            elif mode.transports not in transports_supported:
                click.echo("Mode {} is not supported on this YubiKey!".format(mode))
                ctx.fail("Use --force to attempt to set it anyway.")
            force or click.confirm(
                "Set mode of YubiKey to {}?".format(mode), abort=True, err=True
            )

        try:
            mgmt.set_mode(mode, chalresp_timeout, autoeject)
            click.echo(
                "Mode set! You must remove and re-insert your YubiKey "
                "for this change to take effect."
            )
        except Exception as e:
            logger.debug("Failed to switch mode", exc_info=e)
            click.echo(
                "Failed to switch mode on the YubiKey. Make sure your "
                "YubiKey does not have an access code set."
            )

    else:
        click.echo("Current connection mode is: {}".format(my_mode))
        mode = _mode_from_usb_enabled(info.supported_applications[INTERFACE.USB])
        supported = ", ".join(t.name for t in TRANSPORT if t in mode.transports)
        click.echo("Supported USB interfaces are: {}".format(supported))
