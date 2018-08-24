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

from .util import click_skip_on_help, click_force_option, UpperCaseChoice
from ..device import device_config, FLAGS
from ..util import APPLICATION
from binascii import a2b_hex, b2a_hex
import os
import logging
import click


logger = logging.getLogger(__name__)


CLEAR_LOCK_CODE = '0' * 32


def prompt_lock_code(prompt='Enter your lock code'):
    return click.prompt(prompt, default='', hide_input=True, show_default=False)


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
@click_force_option
@click.option('-l', '--lock-code', metavar='HEX', help='Current lock code.')
@click.option(
    '-n', '--new-lock-code', metavar='HEX',
    help='New lock code. Conflicts with --generate.')
@click.option('-c', '--clear', is_flag=True, help='Clear the lock code.')
@click.option(
    '-g', '--generate', is_flag=True,
    help='Generate a random lock code. Conflicts with --new-lock-code.')
def set_lock_code(ctx, lock_code, new_lock_code, clear, generate, force):
    """
    Set or change the configuration lock code.

    A lock code may be used to protect the application configuration.
    The lock code must be a 32 characters (16 bytes) hex value.
    """

    dev = ctx.obj['dev']

    def prompt_new_lock_code():
        return prompt_lock_code(prompt='Enter your new lock code')

    def prompt_current_lock_code():
        return prompt_lock_code(prompt='Enter your current lock code')

    def change_lock_code(lock_code, new_lock_code):
        lock_code = _parse_lock_code(ctx, lock_code)
        new_lock_code = _parse_lock_code(ctx, new_lock_code)
        try:
            dev.write_config(
                device_config(
                    config_lock=new_lock_code),
                reboot=True,
                lock_key=lock_code)
        except Exception as e:
            logger.error('Changing the lock code failed', exc_info=e)
            ctx.fail('Failed to change the lock code. Wrong current code?')

    def set_lock_code(new_lock_code):
        new_lock_code = _parse_lock_code(ctx, new_lock_code)
        try:
            dev.write_config(
                device_config(
                    config_lock=new_lock_code),
                reboot=True)
        except Exception as e:
            logger.error('Setting the lock code failed', exc_info=e)
            ctx.fail('Failed to set the lock code.')

    if generate and new_lock_code:
        ctx.fail('Invalid options: --new-lock-code conflicts with --generate.')

    if clear:
        new_lock_code = CLEAR_LOCK_CODE

    if generate:
        new_lock_code = b2a_hex(os.urandom(16)).decode('utf-8')
        click.echo(
            'Using a randomly generated lock code: {}'.format(new_lock_code))
        force or click.confirm(
            'Lock configuration with this lock code?', abort=True)

    if dev.config.configuration_locked:
        if lock_code:
            if new_lock_code:
                change_lock_code(lock_code, new_lock_code)
            else:
                new_lock_code = prompt_new_lock_code()
                change_lock_code(lock_code, new_lock_code)
        else:
            if new_lock_code:
                lock_code = prompt_current_lock_code()
                change_lock_code(lock_code, new_lock_code)
            else:
                lock_code = prompt_current_lock_code()
                new_lock_code = prompt_new_lock_code()
                change_lock_code(lock_code, new_lock_code)
    else:
        if lock_code:
            ctx.fail(
                'There is no current lock code set. '
                'Use --new-lock-code to set one.')
        else:
            if new_lock_code:
                set_lock_code(new_lock_code)
            else:
                new_lock_code = prompt_new_lock_code()
                set_lock_code(new_lock_code)


@config.command()
@click.pass_context
@click_force_option
@click.option(
    '-e', '--enable', multiple=True, type=UpperCaseChoice(
        APPLICATION.__members__.keys()), help='Enable applications.')
@click.option(
    '-d', '--disable', multiple=True, type=UpperCaseChoice(
        APPLICATION.__members__.keys()), help='Disable applications.')
@click.option('-l', '--list', is_flag=True, help='List enabled applications.')
@click.option(
    '-a', '--enable-all', is_flag=True, help='Enable all applications.')
@click.option(
    '-L', '--lock-code', metavar='HEX',
    help='Current application configuration lock code.')
@click.option(
    '--touch-eject', is_flag=True, help='When set, the button toggles the state'
    ' of the smartcard between ejected and inserted. (CCID only).')
@click.option(
    '--no-touch-eject', is_flag=True, help='Disable touch eject (CCID only).')
@click.option(
    '--autoeject-timeout', required=False, type=int, default=0,
    metavar='SECONDS', help='When set, the smartcard will automatically eject'
    ' after the given time. Implies --touch-eject.')
@click.option(
    '--chalresp-timeout', required=False, type=int, default=0,
    metavar='SECONDS', help='Sets the timeout when waiting for touch'
    ' for challenge-response in the OTP application.')
def usb(
        ctx, enable, disable, list, enable_all, touch_eject, no_touch_eject,
        autoeject_timeout, chalresp_timeout, lock_code, force):
    """
    Enable or disable applications over USB.
    """

    def ensure_not_all_disabled(ctx, usb_enabled):
        for app in APPLICATION:
            if app & usb_enabled:
                return
        ctx.fail('Can not disable all applications over USB.')

    if not (list or
            enable_all or
            enable or
            disable or
            touch_eject or
            no_touch_eject or
            autoeject_timeout or
            chalresp_timeout):
        ctx.fail('No configuration options chosen.')

    enable = APPLICATION.__members__.keys() if enable_all else enable

    _ensure_not_invalid_options(ctx, enable, disable)

    if touch_eject and no_touch_eject:
        ctx.fail('Invalid options.')

    dev = ctx.obj['dev']

    usb_supported = dev.config.usb_supported
    usb_enabled = dev.config.usb_enabled
    flags = dev.config.device_flags

    if not usb_supported:
        ctx.fail('USB interface not supported.')

    if list:
        _list_apps(ctx, usb_enabled)

    if touch_eject:
        flags |= FLAGS.MODE_FLAG_EJECT
    if no_touch_eject:
        flags &= ~FLAGS.MODE_FLAG_EJECT

    for app in enable:
        if APPLICATION[app] & usb_supported:
            usb_enabled |= APPLICATION[app]
        else:
            ctx.fail('{} not supported over USB.'.format(app))
    for app in disable:
        if APPLICATION[app] & usb_supported:
            usb_enabled &= ~APPLICATION[app]
        else:
            ctx.fail('{} not supported over USB.'.format(app))

    ensure_not_all_disabled(ctx, usb_enabled)

    f_confirm = '{}{}{}{}{}{}Configure USB interface?'.format(
        'Enable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in enable])) if enable else '',
        'Disable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in disable])) if disable else '',
        'Set touch eject.\n' if touch_eject else '',
        'Disable touch eject.\n' if no_touch_eject else '',
        'Set autoeject timeout to {}.\n'.format(
            autoeject_timeout) if autoeject_timeout else '',
        'Set challenge-response timeout to {}.\n'.format(
            chalresp_timeout) if chalresp_timeout else '')

    is_locked = dev.config.configuration_locked

    if force and is_locked and not lock_code:
        ctx.fail('Configuration is locked - please supply the --lock-code '
                 'option.')
    if lock_code and not is_locked:
        ctx.fail('Configuration is not locked - please remove the '
                 '--lock-code option.')

    force or click.confirm(f_confirm, abort=True)

    if is_locked and not lock_code:
        lock_code = prompt_lock_code()

    if lock_code:
        lock_code = _parse_lock_code(ctx, lock_code)

    try:
        dev.write_config(
            device_config(
                usb_enabled=usb_enabled,
                flags=flags,
                auto_eject_timeout=autoeject_timeout,
                chalresp_timeout=chalresp_timeout),
            reboot=True,
            lock_key=lock_code)
    except Exception as e:
        logger.error('Failed to write config', exc_info=e)
        ctx.fail('Failed to configure USB applications.')


@config.command()
@click.pass_context
@click_force_option
@click.option(
    '-e', '--enable', multiple=True, type=UpperCaseChoice(
        APPLICATION.__members__.keys()), help='Enable applications.')
@click.option(
    '-d', '--disable', multiple=True, type=UpperCaseChoice(
        APPLICATION.__members__.keys()), help='Disable applications.')
@click.option(
    '-a', '--enable-all', is_flag=True, help='Enable all applications.')
@click.option(
    '-D', '--disable-all', is_flag=True, help='Disable all applications')
@click.option('-l', '--list', is_flag=True, help='List enabled applications')
@click.option(
    '-L', '--lock-code', metavar='HEX',
    help='Current application configuration lock code.')
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

    _ensure_not_invalid_options(ctx, enable, disable)

    dev = ctx.obj['dev']
    nfc_supported = dev.config.nfc_supported
    nfc_enabled = dev.config.nfc_enabled

    if not nfc_supported:
        ctx.fail('NFC interface not available.')

    if list:
        _list_apps(ctx, nfc_enabled)

    for app in enable:
        if APPLICATION[app] & nfc_supported:
            nfc_enabled |= APPLICATION[app]
        else:
            ctx.fail('{} not supported over NFC.'.format(app))
    for app in disable:
        if APPLICATION[app] & nfc_supported:
            nfc_enabled &= ~APPLICATION[app]
        else:
            ctx.fail('{} not supported over NFC.'.format(app))

    f_confirm = '{}{}Configure NFC interface?'.format(
        'Enable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in enable])) if enable else '',
        'Disable {}.\n'.format(
            ', '.join(
                [str(APPLICATION[app]) for app in disable])) if disable else '')

    is_locked = dev.config.configuration_locked

    if force and is_locked and not lock_code:
        ctx.fail('Configuration is locked - please supply the --lock-code '
                 'option.')
    if lock_code and not is_locked:
        ctx.fail('Configuration is not locked - please remove the '
                 '--lock-code option.')

    force or click.confirm(f_confirm, abort=True)

    if is_locked and not lock_code:
        lock_code = prompt_lock_code()

    if lock_code:
        lock_code = _parse_lock_code(ctx, lock_code)

    try:
        dev.write_config(
            device_config(
                nfc_enabled=nfc_enabled),
            reboot=True, lock_key=lock_code)
    except Exception as e:
        logger.error('Failed to write config', exc_info=e)
        ctx.fail('Failed to configure NFC applications.')


def _list_apps(ctx, enabled):
    for app in APPLICATION:
        if app & enabled:
            click.echo(str(app))
    ctx.exit()


def _ensure_not_invalid_options(ctx, enable, disable):
    if any(a in enable for a in disable):
        ctx.fail('Invalid options.')


def _parse_lock_code(ctx, lock_code):
    try:
        lock_code = a2b_hex(lock_code)
        if lock_code and len(lock_code) != 16:
            ctx.fail('Lock code must be exactly 16 bytes '
                     '(32 hexadecimal digits) long.')
        return lock_code
    except Exception:
        ctx.fail('Lock code has the wrong format.')
