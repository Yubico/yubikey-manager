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
import click
import logging
from fido2.ctap import CtapError
from time import sleep
from .util import click_skip_on_help, prompt_for_touch, click_force_option
from ..driver_ccid import (
    APDUError, SW_COMMAND_NOT_ALLOWED, SW_VERIFY_FAIL_NO_RETRY,
    SW_AUTH_METHOD_BLOCKED, SW_DATA_INVALID)
from ..util import TRANSPORT
from ..fido import Fido2Controller, FipsU2fController
from ..descriptor import get_descriptors


logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
@click_skip_on_help
def fido(ctx):
    """
    Manage FIDO applications.
    """
    if ctx.obj['dev'].is_fips:
        ctx.obj['controller'] = FipsU2fController(ctx.obj['dev'].driver)
    else:
        try:
            ctx.obj['controller'] = Fido2Controller(ctx.obj['dev'].driver)
        except Exception as e:
            logger.debug('Failed to load Fido2Controller', exc_info=e)
            ctx.fail('Failed to load FIDO 2 Application.')


@fido.command()
@click.pass_context
def info(ctx):
    """
    Display status of FIDO2 application.
    """
    controller = ctx.obj['controller']

    if controller.is_fips:
        if controller.is_in_fips_mode:
            click.echo('FIPS mode active: Yes')
        else:
            click.echo('FIPS mode active: No')
            click.echo('This could mean that a PIN is not set, or that the '
                       'FIDO U2F module has been reset and is no longer '
                       'capable of FIPS mode.')
    else:
        if controller.has_pin:
            try:
                click.echo(
                    'PIN is set, with {} tries left.'.format(
                        controller.get_pin_retries()))
            except CtapError as e:
                if e.code == CtapError.ERR.PIN_BLOCKED:
                    click.echo('PIN is blocked.')
        else:
            click.echo('PIN is not set.')


@fido.command('set-pin')
@click.pass_context
@click.option('-P', '--pin', help='Current PIN code.')
@click.option('-n', '--new-pin', help='A new PIN.')
@click.option('--u2f', is_flag=True,
              help='Set FIPS U2F PIN instead of FIDO2 PIN')
def set_pin(ctx, pin, new_pin, u2f):
    """
    Set or change the PIN code.

    The PIN must be at least 4 characters long, and supports any type
    of alphanumeric characters.
    """

    controller = ctx.obj['controller']

    if controller.is_fips and not u2f:
        ctx.fail('This is a FIPS YubiKey. To set the U2F PIN, pass the --u2f '
                 'option.')

    if u2f and not controller.is_fips:
        ctx.fail('This is not a FIPS YubiKey, and therefore does not support a '
                 'U2F PIN. To set the FIDO2 PIN, remove the --u2f option.')

    def fail_if_not_valid(ctx, pin=None):
        if not pin or len(pin) < 4 or len(pin.encode('utf-8')) > 128:
            ctx.fail('PIN must be over 4 characters long and under 128 bytes.')

    def prompt_new_pin():
        return click.prompt(
                    'Enter your new PIN', default='', hide_input=True,
                    show_default=False, confirmation_prompt=True)

    def prompt_current_pin():
        return click.prompt(
                    'Enter your current PIN', default='', hide_input=True,
                    show_default=False)

    def change_pin(pin, new_pin, accept_empty_current_pin=False):
        if not (accept_empty_current_pin and pin == ''):
            fail_if_not_valid(ctx, pin)
        fail_if_not_valid(ctx, new_pin)
        try:
            controller.change_pin(old_pin=pin, new_pin=new_pin)

        except CtapError as e:
            if e.code == CtapError.ERR.PIN_INVALID:
                ctx.fail('Wrong PIN.')
            if e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                ctx.fail(
                    'PIN authentication is currently blocked. '
                    'Remove and re-insert the YubiKey.')
            if e.code == CtapError.ERR.PIN_BLOCKED:
                ctx.fail('PIN is blocked.')
            logger.error('Failed to change PIN', exc_info=e)
            ctx.fail('Failed to change PIN.')

        except APDUError as e:
            if e.sw == SW_DATA_INVALID:
                ctx.fail('No PIN is set.')

            if e.sw == SW_VERIFY_FAIL_NO_RETRY:
                ctx.fail('Wrong PIN.')

            if e.sw == SW_AUTH_METHOD_BLOCKED:
                ctx.fail('Too many incorrect PIN attempts - PIN is blocked.\n'
                         'Use the "fido reset" command to reset.')

            logger.error('Failed to change PIN', exc_info=e)
            ctx.fail('Failed to change PIN.')

    def set_pin(new_pin):
        fail_if_not_valid(ctx, new_pin)
        controller.set_pin(new_pin)

    if pin and not controller.has_pin:
        ctx.fail('There is no current PIN set. Use -n/--new-pin to set one.')

    if controller.has_pin and pin is None:
        pin = prompt_current_pin()

    if not new_pin:
        new_pin = prompt_new_pin()

    if controller.has_pin:
        change_pin(pin, new_pin, accept_empty_current_pin=controller.is_fips)
    else:
        set_pin(new_pin)


@click_force_option
@fido.command('reset')
@click.confirmation_option(
            '-f', '--force', prompt='WARNING! This will delete '
            'all FIDO credentials, including FIDO U2F credentials,'
            ' and restore factory settings. Proceed?')
@click.pass_context
def reset(ctx, force):
    """
    Reset all FIDO applications.

    This action will wipe all FIDO credentials, including FIDO U2F credentials,
    on the YubiKey and remove the PIN code.

    The reset must be triggered immediately after the YubiKey is
    inserted, and requires a touch on the YubiKey.
    """

    def prompt_re_insert_key():
        click.echo('Remove and re-insert your YubiKey to perform the reset...')

        removed = False
        while True:
            sleep(0.1)
            n_keys = len(list(get_descriptors()))
            if not n_keys:
                removed = True
            if removed and n_keys == 1:
                return

    def try_reset(controller_type):
        if not force:
            prompt_re_insert_key()
            dev = list(get_descriptors())[0].open_device(TRANSPORT.FIDO)
            controller = controller_type(dev.driver)
            controller.reset(touch_callback=prompt_for_touch)
        else:
            controller = ctx.obj['controller']
            controller.reset(touch_callback=prompt_for_touch)

    if ctx.obj['dev'].is_fips:
        if not force:
            click.echo(
                '\nWARNING: This will destroy the FIPS attestation key, making '
                'this YubiKey permanently incapable of FIPS mode.'
            )
            destroy_input = click.prompt(
                'To confirm, please enter the text "DESTROY PERMANENTLY"',
                default='',
                show_default=False
            )
            if destroy_input != 'DESTROY PERMANENTLY':
                ctx.fail('Reset aborted by user.')

        try:
            try_reset(FipsU2fController)

        except APDUError as e:
            if e.sw == SW_COMMAND_NOT_ALLOWED:
                ctx.fail(
                    'Reset failed. Reset must be triggered within 5 seconds'
                    ' after the YubiKey is inserted.')
            else:
                logger.error('Reset failed', exc_info=e)
                ctx.fail('Reset failed.')

        except Exception as e:
            logger.error('Reset failed', exc_info=e)
            ctx.fail('Reset failed.')

    else:
        try:
            try_reset(Fido2Controller)
        except CtapError as e:
            if e.code == CtapError.ERR.ACTION_TIMEOUT:
                ctx.fail(
                    'Reset failed. You need to touch your'
                    ' YubiKey to confirm the reset.')
            elif e.code == CtapError.ERR.NOT_ALLOWED:
                ctx.fail(
                    'Reset failed. Reset must be triggered within 5 seconds'
                    ' after the YubiKey is inserted.')
            else:
                logger.error(e)
                ctx.fail('Reset failed.')
        except Exception as e:
            logger.error(e)
            ctx.fail('Reset failed.')


fido.transports = TRANSPORT.FIDO
