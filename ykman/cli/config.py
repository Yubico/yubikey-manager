# Copyright (c) 2018 Yubico AB
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

from .util import click_skip_on_help, click_force_option
from ..device import device_config
from ..util import APPLICATION
import logging
import click


logger = logging.getLogger(__name__)


APPLICATIONS = ['OTP', 'FIDO2', 'U2F', 'OPGP', 'OATH', 'PIV']


@click.group()
@click.pass_context
@click_skip_on_help
def config(ctx):
    """
    Enable/Disable applications.

    The applications may be enabled and disabled independently
    over different interfaces (USB and NFC). The configuration may
    also be protected by a lock code.
    """
    pass


@config.command('set-lock-code')
@click.pass_context
def set_lock_code(ctx):
    """
    Protect the configuration with a lock code.
    """
    pass


@config.command()
@click.pass_context
@click_force_option
@click.option(
    '-e', '--enable', multiple=True, type=click.Choice(APPLICATIONS),
    help='Enable applications.')
@click.option(
    '-d', '--disable', multiple=True, type=click.Choice(APPLICATIONS),
    help='Disable applications.')
@click.option(
    '-l', '--lock-code',
    help='Lock code used to protect the application configuration.')
@click.option(
    '--touch-eject', is_flag=True, help='When set, the button toggles the state'
    ' of the smartcard between ejected and inserted. '
    '(CCID only).')
@click.option(
    '--autoeject-timeout', required=False, type=int, default=0,
    metavar='SECONDS', help='When set, the smartcard will automatically eject'
    ' after the given time. Implies --touch-eject.')
@click.option(
    '--chalresp-timeout', required=False, type=int, default=0,
    metavar='SECONDS', help='Sets the timeout when waiting for touch'
    ' for challenge response in the OTP application.')
def usb(
        ctx, enable, disable, touch_eject, autoeject_timeout, chalresp_timeout,
        lock_code, force):
    """
    Enable or disable applications over USB.
    """
    dev = ctx.obj['dev']
    usb_enabled = dev.config.usb_enabled

    for app in enable:
        usb_enabled |= APPLICATION[app]
    for app in disable:
        usb_enabled &= ~APPLICATION[app]

    f_confirm = '{}{}Configure USB interface?'.format(
        'Enable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in enable])) if enable else '',
        'Disable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in disable])) if disable else '')

    force or click.confirm(f_confirm, abort=True)

    dev.write_config(device_config(usb_enabled=usb_enabled), reboot=True)


@config.command()
@click.pass_context
@click_force_option
@click.option(
    '-e', '--enable', multiple=True, type=click.Choice(APPLICATIONS),
    help='Enable applications.')
@click.option(
    '-d', '--disable', multiple=True, type=click.Choice(APPLICATIONS),
    help='Disable applications.')
@click.option(
    '-l', '--lock-code',
    help='Lock code used to protect the application configuration.')
def nfc(ctx, enable, disable, lock_code, force):
    """
    Enable or disable applications over NFC.
    """
    dev = ctx.obj['dev']
    nfc_enabled = dev.config.nfc_enabled
    for app in enable:
        nfc_enabled |= APPLICATION[app]

    for app in disable:
        nfc_enabled &= ~APPLICATION[app]

    f_confirm = '{}{}Configure NFC interface?'.format(
        'Enable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in enable])) if enable else '',
        'Disable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in disable])) if disable else '')

    force or click.confirm(f_confirm, abort=True)

    dev.write_config(device_config(nfc_enabled=nfc_enabled), reboot=True)
