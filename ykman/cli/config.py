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
from ..device import device_config, FLAGS
from ..util import APPLICATION
import logging
import click


logger = logging.getLogger(__name__)


CLEAR_LOCK_CODE = (
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


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
    dev = ctx.obj['dev']
    if not dev.can_write_config:
        ctx.fail('Configuring applications is not supported on this YubiKey. '
                 'Use the `mode` command to configure USB interfaces.')


@config.command('set-lock-code')
@click.pass_context
@click.option('-l', '--lock-code', help='Current lock code.')
@click.option('-n', '--new-lock-code', help='New lock code.')
@click.option('-c', '--clear', is_flag=True, help='Clear the lock code.')
def set_lock_code(ctx, lock_code, new_lock_code, clear):
    """
    Set or change the configuration lock code.

    A 16 byte lock code may be used to protect the application configuration.
    """
    dev = ctx.obj['dev']
    if lock_code:
        lock_code = lock_code.encode()
    if new_lock_code:
        new_lock_code = new_lock_code.encode()
    if clear:
        new_lock_code = CLEAR_LOCK_CODE
    dev.write_config(
        device_config(
            config_lock=new_lock_code), reboot=True, lock_key=lock_code)


@config.command()
@click.pass_context
@click_force_option
@click.option(
    '-e', '--enable', multiple=True, type=click.Choice(
        APPLICATION.__members__.keys()), help='Enable applications.')
@click.option(
    '-d', '--disable', multiple=True, type=click.Choice(
        APPLICATION.__members__.keys()), help='Disable applications.')
@click.option('-l', '--list', is_flag=True, help='List enabled applications.')
@click.option(
    '-a', '--enable-all', is_flag=True, help='Enable all applications.')
@click.option(
    '-L', '--lock-code',
    help='A 16 byte lock code used to protect the application configuration.')
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
    ' for challenge-response in the OTP application.')
def usb(
        ctx, enable, disable, list, enable_all, touch_eject, autoeject_timeout,
        chalresp_timeout, lock_code, force):
    """
    Enable or disable applications over USB.
    """

    if not (list or
            enable_all or
            enable or
            disable or
            touch_eject or
            autoeject_timeout or
            chalresp_timeout):
        ctx.fail('No configuration options chosen.')

    if enable_all:
        enable = APPLICATION.__members__.keys()

    if any(a in enable for a in disable):
        ctx.fail('Invalid options.')

    dev = ctx.obj['dev']
    usb_enabled = dev.config.usb_enabled
    flags = dev.config.device_flags
    if list:
        for app in APPLICATION:
            if app & usb_enabled:
                click.echo(str(app))
        ctx.exit()

    if touch_eject:
        flags |= FLAGS.MODE_FLAG_EJECT
    else:
        #  Disable if flag not provided.
        flags &= ~FLAGS.MODE_FLAG_EJECT

    if lock_code:
        lock_code = lock_code.encode()
        if len(lock_code) != 16:
            ctx.fail('Lock code must be 16 bytes.')
    for app in enable:
        usb_enabled |= APPLICATION[app]
    for app in disable:
        usb_enabled &= ~APPLICATION[app]

    f_confirm = '{}{}{}{}{}Configure USB interface?'.format(
        'Enable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in enable])) if enable else '',
        'Disable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in disable])) if disable else '',
        'Set touch eject.\n' if touch_eject else '',
        'Set autoeject timeout to {}.\n'.format(
            autoeject_timeout) if autoeject_timeout else '',
        'Set challenge-response timeout to {}.\n'.format(
            chalresp_timeout) if chalresp_timeout else '')

    force or click.confirm(f_confirm, abort=True)
    dev.write_config(
        device_config(
            usb_enabled=usb_enabled,
            flags=flags,
            auto_eject_timeout=autoeject_timeout,
            chalresp_timeout=chalresp_timeout),
        reboot=True,
        lock_key=lock_code)


@config.command()
@click.pass_context
@click_force_option
@click.option(
    '-e', '--enable', multiple=True, type=click.Choice(
        APPLICATION.__members__.keys()), help='Enable applications.')
@click.option(
    '-d', '--disable', multiple=True, type=click.Choice(
        APPLICATION.__members__.keys()), help='Disable applications.')
@click.option(
    '-a', '--enable-all', is_flag=True, help='Enable all applications.')
@click.option(
    '-D', '--disable-all', is_flag=True, help='Disable all applications')
@click.option('-l', '--list', is_flag=True, help='List enabled applications')
@click.option(
    '-L', '--lock-code',
    help='A 16 byte lock code used to protect the application configuration.')
def nfc(ctx, enable, disable, enable_all, disable_all, list, lock_code, force):
    """
    Enable or disable applications over NFC.
    """
    if not (list or enable_all or enable or disable_all or disable):
        ctx.fail('No configuration options chosen.')

    if enable_all:
        enable = APPLICATION.__members__.keys()

    if disable_all:
        disable = APPLICATION.__members__.keys()

    if any(a in enable for a in disable):
        ctx.fail('Invalid options.')

    if lock_code:
        lock_code = lock_code.encode()
        if len(lock_code) != 16:
            ctx.fail('Lock code must be 16 bytes.')

    dev = ctx.obj['dev']
    nfc_enabled = dev.config.nfc_enabled

    if list:
        for app in APPLICATION:
            if app & nfc_enabled:
                click.echo(str(app))
        ctx.exit()

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

    dev.write_config(
        device_config(nfc_enabled=nfc_enabled), reboot=True, lock_key=lock_code)
