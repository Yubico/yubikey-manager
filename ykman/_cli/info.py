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
from yubikit.support import get_name

from .util import CliFail, is_yk4_fips, click_command
from ..otp import is_in_fips_mode as otp_in_fips_mode
from ..oath import is_in_fips_mode as oath_in_fips_mode
from ..fido import is_in_fips_mode as ctap_in_fips_mode
from typing import List

import click
import logging


logger = logging.getLogger(__name__)


def print_app_status_table(supported_apps, enabled_apps):
    usb_supported = supported_apps.get(TRANSPORT.USB, 0)
    usb_enabled = enabled_apps.get(TRANSPORT.USB, 0)
    nfc_supported = supported_apps.get(TRANSPORT.NFC, 0)
    nfc_enabled = enabled_apps.get(TRANSPORT.NFC, 0)
    rows = []
    for app in CAPABILITY:
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
            rows.append([app.display_name, usb_status, nfc_status])
        else:
            rows.append([app.display_name, usb_status])

    column_l: List[int] = []
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
        f_table = f_table.strip() + "\n"

    if nfc_supported:
        click.echo(f"{f_apps}\t{f_USB}\t{f_NFC}")
    else:
        click.echo(f"{f_apps}")
    click.echo(f_table, nl=False)


def get_overall_fips_status(device, info):
    statuses = {}

    usb_enabled = info.config.enabled_capabilities[TRANSPORT.USB]

    statuses["OTP"] = False
    if usb_enabled & CAPABILITY.OTP:
        with device.open_connection(OtpConnection) as conn:
            otp_app = YubiOtpSession(conn)
            statuses["OTP"] = otp_in_fips_mode(otp_app)

    statuses["OATH"] = False
    if usb_enabled & CAPABILITY.OATH:
        with device.open_connection(SmartCardConnection) as conn:
            oath_app = OathSession(conn)
            statuses["OATH"] = oath_in_fips_mode(oath_app)

    statuses["FIDO U2F"] = False
    if usb_enabled & CAPABILITY.U2F:
        with device.open_connection(FidoConnection) as conn:
            statuses["FIDO U2F"] = ctap_in_fips_mode(conn)

    return statuses


def _check_fips_status(device, info):
    fips_status = get_overall_fips_status(device, info)
    click.echo()

    click.echo(f"FIPS Approved Mode: {'Yes' if all(fips_status.values()) else 'No'}")

    status_keys = list(fips_status.keys())
    status_keys.sort()
    for status_key in status_keys:
        click.echo(f"  {status_key}: {'Yes' if fips_status[status_key] else 'No'}")


@click.option(
    "-c",
    "--check-fips",
    help="check if YubiKey is in FIPS Approved mode (YubiKey 4 FIPS only)",
    is_flag=True,
)
@click_command(connections=[SmartCardConnection, OtpConnection, FidoConnection])
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
        interfaces = pid.usb_interfaces
        key_type = pid.yubikey_type
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
            t.name or str(t) for t in USB_INTERFACE if t in USB_INTERFACE(interfaces)
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
        if is_yk4_fips(info):
            device = ctx.obj["device"]
            _check_fips_status(device, info)
        else:
            raise CliFail("Unable to check FIPS Approved mode - Not a YubiKey 4 FIPS")
