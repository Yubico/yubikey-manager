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

from __future__ import absolute_import

from ..util import APPLICATION
import click


@click.command()
@click.pass_context
def info(ctx):
    """
    Show general information.

    Displays information about the attached YubiKey such as serial number,
    firmware version, applications, etc.
    """
    dev = ctx.obj['dev']
    click.echo('Device type: {}'.format(dev.device_name))
    click.echo('Serial number: {}'.format(
        dev.serial or 'Not set or unreadable'))
    if dev.version:
        f_version = '.'.join(str(x) for x in dev.version)
        click.echo('Firmware version: {}'.format(f_version))
    else:
        click.echo('Firmware version: Uncertain, re-run with only one '
                   'YubiKey connected')
    config = dev.config
    if config.form_factor:
        click.echo('Form factor: {!s}'.format(config.form_factor))
    click.echo('Enabled USB interfaces: {}'.format(dev.mode))
    if config.nfc_supported:
        f_nfc = 'enabled' if config.nfc_enabled else 'disabled'
        click.echo('NFC interface is {}.'.format(f_nfc))
    if config.configuration_locked:
        click.echo('Configured applications are protected by a lock code.')
    click.echo()
    rows = []
    for app in APPLICATION:
        if app & config.usb_supported:
            if app & config.usb_enabled:
                usb_status = 'Enabled'
            else:
                usb_status = 'Disabled'
        else:
            usb_status = 'Not available'
        if config.nfc_supported:
            if app & config.nfc_supported:
                if app & config.nfc_enabled:
                    nfc_status = 'Enabled'
                else:
                    nfc_status = 'Disabled'
            else:
                nfc_status = 'Not available'
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

    f_apps = 'Applications'.ljust(column_l[0])
    if config.nfc_supported:
        f_USB = 'USB'.ljust(column_l[1])
        f_NFC = 'NFC'.ljust(column_l[2])
    f_table = ''

    for row in rows:
        for idx, c in enumerate(row):
            f_table += '{}\t'.format(c.ljust(column_l[idx]))
        f_table += '\n'

    if config.nfc_supported:
        click.echo('{}\t{}\t{}'.format(f_apps, f_USB, f_NFC))
    else:
        click.echo('{}'.format(f_apps))
    click.echo(f_table, nl=False)
