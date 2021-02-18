# Copyright (c) 2016 Yubico AB
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

from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import CAPABILITY, USB_INTERFACE
from yubikit.yubiotp import YubiOtpSession
from yubikit.oath import OathSession

from .util import cli_fail
from ..device import is_fips_version, get_name, connect_to_device
from ..otp import is_in_fips_mode as otp_in_fips_mode
from ..oath import is_in_fips_mode as oath_in_fips_mode
from ..fido import is_in_fips_mode as ctap_in_fips_mode

import click
import logging


logger = logging.getLogger(__name__)

SHOWN_CAPABILITIES = set(CAPABILITY) - {CAPABILITY.HSMAUTH}


def print_app_status_table(supported_apps, enabled_apps):
    usb_supported = supported_apps.get(TRANSPORT.USB, 0)
    usb_enabled = enabled_apps.get(TRANSPORT.USB, 0)
    nfc_supported = supported_apps.get(TRANSPORT.NFC, 0)
    nfc_enabled = enabled_apps.get(TRANSPORT.NFC, 0)
    rows = []
    for app in SHOWN_CAPABILITIES:
        if app & usb_supported:
            if app & usb_enabled:
                usb_status = "Enabled"
            else:
                usb_status = "Disabled"
        else:
            usb_status = "Not available"
        if nfc_supported:
            if app & nfc_supported:
                if app & nfc_enabled:
                    nfc_status = "Enabled"
                else:
                    nfc_status = "Disabled"
            else:
                nfc_status = "Not available"
            rows.append([str(app), usb_status, nfc_status])
        else:
            rows.append([str(app), usb_status])

    column_l = []
    for row in rows:
        for idx, c in enumerate(row):
            if len(column_l) > idx:
                if len(c) > column_l[idx]:
                    column_l[idx] = len(c)
            else:
                column_l.append(len(c))

    f_apps = "Applications".ljust(column_l[0])
    if nfc_supported:
        f_USB = "USB".ljust(column_l[1])
        f_NFC = "NFC".ljust(column_l[2])
    f_table = ""

    for row in rows:
        for idx, c in enumerate(row):
            f_table += f"{c.ljust(column_l[idx])}\t"
        f_table += "\n"

    if nfc_supported:
        click.echo(f"{f_apps}\t{f_USB}\t{f_NFC}")
    else:
        click.echo(f"{f_apps}")
    click.echo(f_table, nl=False)


def get_overall_fips_status(pid, info):
    statuses = {}

    usb_enabled = info.config.enabled_capabilities[TRANSPORT.USB]

    statuses["OTP"] = False
    if usb_enabled & CAPABILITY.OTP:
        with connect_to_device(info.serial, [OtpConnection])[0] as conn:
            app = YubiOtpSession(conn)
            statuses["OTP"] = otp_in_fips_mode(app)

    statuses["OATH"] = False
    if usb_enabled & CAPABILITY.OATH:
        with connect_to_device(info.serial, [SmartCardConnection])[0] as conn:
            app = OathSession(conn)
            statuses["OATH"] = oath_in_fips_mode(app)

    statuses["FIDO U2F"] = False
    if usb_enabled & CAPABILITY.U2F:
        with connect_to_device(info.serial, [FidoConnection])[0] as conn:
            statuses["FIDO U2F"] = ctap_in_fips_mode(conn)

    return statuses


def _check_fips_status(pid, info):
    fips_status = get_overall_fips_status(pid, info)
    click.echo()

    click.echo(f"FIPS Approved Mode: {'Yes' if all(fips_status.values()) else 'No'}")

    status_keys = list(fips_status.keys())
    status_keys.sort()
    for status_key in status_keys:
        click.echo(f"  {status_key}: {'Yes' if fips_status[status_key] else 'No'}")


@click.option(
    "-c",
    "--check-fips",
    help="Check if YubiKey is in FIPS Approved mode (YubiKey FIPS only).",
    is_flag=True,
)
@click.command()
@click.pass_context
def info(ctx, check_fips):
    """
    Show general information.

    Displays information about the attached YubiKey such as serial number,
    firmware version, capabilities, etc.
    """
    info = ctx.obj["info"]
    pid = ctx.obj["pid"]
    if pid is None:
        interfaces = None
        key_type = None
    else:
        interfaces = pid.get_interfaces()
        key_type = pid.get_type()
    device_name = get_name(info, key_type)

    click.echo(f"Device type: {device_name}")
    if info.serial:
        click.echo(f"Serial number: {info.serial}")
    if info.version:
        f_version = ".".join(str(x) for x in info.version)
        click.echo(f"Firmware version: {f_version}")
    else:
        click.echo(
            "Firmware version: Uncertain, re-run with only one YubiKey connected"
        )

    if info.form_factor:
        click.echo(f"Form factor: {info.form_factor!s}")
    if interfaces:
        f_interfaces = ", ".join(
            t.name for t in USB_INTERFACE if t in USB_INTERFACE(interfaces)
        )
        click.echo(f"Enabled USB interfaces: {f_interfaces}")
    if TRANSPORT.NFC in info.supported_capabilities:
        f_nfc = (
            "enabled"
            if info.config.enabled_capabilities.get(TRANSPORT.NFC)
            else "disabled"
        )
        click.echo(f"NFC transport is {f_nfc}.")
    if info.is_locked:
        click.echo("Configured capabilities are protected by a lock code.")
    click.echo()

    print_app_status_table(
        info.supported_capabilities, info.config.enabled_capabilities
    )

    if check_fips:
        if is_fips_version(info.version):
            ctx.obj["conn"].close()
            _check_fips_status(pid, info)
        else:
            cli_fail("Not a YubiKey FIPS")
