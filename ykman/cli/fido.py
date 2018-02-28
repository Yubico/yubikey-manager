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
from .util import click_skip_on_help, prompt_for_touch
from ..driver_u2f import U2FHostError
from ..util import TRANSPORT
from ..fido import Fido2Controller, CTAP2Error, CTAP2_ERR


logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
@click_skip_on_help
def fido(ctx):
    """
    Manage YubiKey FIDO 2 credentials.
    """
    try:
        ctx.obj['controller'] = Fido2Controller(ctx.obj['dev'].driver)
    except U2FHostError:
        ctx.fail('FIDO functionality not supported.')


@fido.command()
@click.pass_context
def info(ctx):
    """
    Display status of FIDO 2 functionality.
    """
    controller = ctx.obj['controller']
    if controller.has_pin:
        try:
            click.echo(
                'PIN is set, with {} tries left.'.format(
                    controller.get_pin_retries()))
        except CTAP2Error as e:
            if e.code == CTAP2_ERR.PIN_BLOCKED:
                click.echo('PIN is blocked.')
    else:
        click.echo('PIN is not set.')


@fido.command('set-pin')
@click.pass_context
@click.option('-P', '--pin', help='Current PIN code.')
@click.option('-n', '--new-pin', help='A new PIN.')
def set_pin(ctx, pin, new_pin):
    """
    Set or change the PIN code.

    The PIN must be at least 4 characters long, and supports any type
    of alphanumeric characters.
    """

    controller = ctx.obj['controller']

    def prompt_new_pin():
        return click.prompt(
                    'Enter your new PIN', default='', hide_input=True,
                    show_default=False, confirmation_prompt=True)

    def prompt_current_pin():
        return click.prompt(
                    'Enter your current PIN', default='', hide_input=True,
                    show_default=False)

    def change_pin(pin, new_pin):
        try:
            controller.change_pin(old_pin=pin, new_pin=new_pin)
        except CTAP2Error as e:
            if e.code == CTAP2_ERR.PIN_INVALID:
                ctx.fail('Wrong PIN.')
            if e.code == CTAP2_ERR.PIN_AUTH_BLOCKED:
                ctx.fail(
                    'PIN authentication is currently blocked.'
                    'Remove and re-insert the YubiKey.')
            if e.code == CTAP2_ERR.PIN_BLOCKED:
                ctx.fail('PIN is blocked.')
            ctx.fail('Failed to change PIN. {}.'.format(e.message))

    def set_pin(new_pin):
        try:
            controller.set_pin(new_pin)
        except Exception as e:
            logger.error('Failed to set PIN', exc_info=e)
            ctx.fail('Failed to set a PIN.')

    if controller.has_pin:
        if pin:
            if new_pin:
                change_pin(pin, new_pin)
            else:
                new_pin = prompt_new_pin()
                change_pin(pin, new_pin)
        else:
            if new_pin:
                pin = prompt_current_pin()
                change_pin(pin, new_pin)
            else:
                pin = prompt_current_pin()
                new_pin = prompt_new_pin()
                change_pin(pin, new_pin)
    else:
        if pin:
            ctx.fail(
                'There is no current PIN set. Use -n/--new-pin to set one.')
        else:
            if new_pin:
                set_pin(new_pin)
            else:
                new_pin = prompt_new_pin()
                set_pin(new_pin)


@fido.command('reset')
@click.confirmation_option(
            '-f', '--force', prompt='WARNING! This will delete '
            'all FIDO credentials, including FIDO U2F credentials,'
            ' and restore factory settings. Proceed?')
@click.pass_context
def reset(ctx):
    """
    Reset all FIDO functionality.

    This action will wipe all FIDO credentials, including FIDO U2F credentials,
    on the YubiKey and remove the PIN code.

    The reset must be triggered immediately after the YubiKey is
    inserted, and requires a touch on the YubiKey.
    """
    controller = ctx.obj['controller']
    try:
        controller.reset()
    except CTAP2Error as e:
        if e.code == CTAP2_ERR.NOT_ALLOWED:
            ctx.fail(
                'Failed to reset the YubiKey. The reset command must be '
                'triggered immediately after the YubiKey is inserted.')
        else:
            raise
    except U2FHostError as e:
        # Might not be needed with new libu2f-host
        logger.debug(e)
        pass
    except Exception as e:
        logger.error(e)
        ctx.fail('Failed to reset the YubiKey.')
    prompt_for_touch()


fido.transports = TRANSPORT.U2F
