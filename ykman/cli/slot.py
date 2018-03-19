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

from .util import (
    click_force_option, click_callback, click_parse_b32_key,
    click_skip_on_help, prompt_for_touch)
from ..util import (
    TRANSPORT, generate_static_pw, modhex_decode,
    modhex_encode, parse_key, parse_b32_key)
from binascii import a2b_hex, b2a_hex
from ..driver_otp import YkpersError
from ..scancodes import KEYBOARD_LAYOUT
import logging
import os
import struct
import click


logger = logging.getLogger(__name__)


def parse_hex(length):
    @click_callback()
    def inner(ctx, param, val):
        val = a2b_hex(val)
        if len(val) != length:
            raise ValueError('Must be exactly {} bytes.'.format(length))
        return val
    return inner


click_slot_argument = click.argument('slot', type=click.Choice(['1', '2']),
                                     callback=lambda c, p, v: int(v))


def _failed_to_write_msg(ctx, exc_info):
    logger.error('Failed to write to device', exc_info=exc_info)
    ctx.fail('Failed to write to the YubiKey. Make sure the device does not '
             'have restricted access.')


def _confirm_slot_overwrite(dev, slot):
    slot1, slot2 = dev.driver.slot_status
    if slot == 1 and slot1:
        click.confirm(
            'Slot 1 is already configured. Overwrite configuration?',
            abort=True)
    if slot == 2 and slot2:
        click.confirm(
            'Slot 2 is already configured. Overwrite configuration?',
            abort=True)


@click.group()
@click.pass_context
@click_skip_on_help
@click.option(
    '--access-code', required=False, metavar='HEX',
    help='A 6 byte access code. Set to empty to use a prompt for input.')
def slot(ctx, access_code):
    """
    Manage YubiKey Slots.

    The YubiKey provides two keyboard-based slots which can each be configured
    with a credential. Several credential types are supported.

    A slot configuration may be write-protected with an access code. This
    prevents the configuration to be overwritten without the access code
    provided. Mode switching the YubiKey is not possible when a slot is
    configured with an access code.
    """

    if access_code is not None:
        if access_code == '':
            access_code = click.prompt('Enter access code', show_default=False)
        try:
            access_code = a2b_hex(access_code)
        except TypeError as e:
            raise ValueError(e)
        if len(access_code) != 6:
            raise ValueError('Must be exactly 6 bytes.')
    ctx.obj['dev'].driver.access_code = access_code


@slot.command()
@click.pass_context
def info(ctx):
    """
    Display status of YubiKey Slots.
    """
    dev = ctx.obj['dev']
    click.echo(dev.device_name)
    slot1, slot2 = dev.driver.slot_status
    click.echo('Slot 1: {}'.format(slot1 and 'programmed' or 'empty'))
    click.echo('Slot 2: {}'.format(slot2 and 'programmed' or 'empty'))


@slot.command()
@click.confirmation_option('-f', '--force', prompt='Swap the two slots of the '
                           'YubiKey?')
@click.pass_context
def swap(ctx):
    """
    Swaps the two slot configurations.
    """
    dev = ctx.obj['dev']
    click.echo('Swapping slots...')
    try:
        dev.driver.swap_slots()
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@slot.command()
@click_slot_argument
@click_force_option
@click.pass_context
def delete(ctx, slot, force):
    """
    Deletes the configuration of a slot.
    """
    dev = ctx.obj['dev']
    if not force and not dev.driver.slot_status[slot - 1]:
        ctx.fail('Not possible to delete an empty slot.')
    force or click.confirm(
        'Do you really want to delete'
        ' the configuration of slot {}?'.format(slot), abort=True)
    click.echo('Deleting the configuration of slot {}...'.format(slot))
    try:
        dev.driver.zap_slot(slot)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@slot.command()
@click_slot_argument
@click.option('-P', '--public-id', required=False,
              help='Static part of the OTP, defaults to the YubiKey serial '
              'number converted to modhex.', metavar='MODHEX')
@click.option('-p', '--private-id', required=False, metavar='HEX',
              callback=parse_hex(6), help='6 byte private identifier of the '
              'credential.')
@click.option('-k', '--key', required=False, metavar='HEX',
              callback=parse_hex(16), help='16 byte secret key, in hex.')
@click.option('--no-enter', is_flag=True, help="Don't send an Enter "
              'keystroke after outputting an OTP.')
@click_force_option
@click.pass_context
def otp(ctx, slot, public_id, private_id, key, no_enter, force):
    """
    Program a Yubico OTP credential.

    """

    dev = ctx.obj['dev']

    if not public_id:
        if not force:
            public_id = click.prompt(
                'Enter public ID [blank to use YubiKey serial number]',
                default='',
                show_default=False)
        if force or public_id == '':
            if dev.serial is None:
                ctx.fail('Serial number not set, public ID must be provided')
            public_id = modhex_encode(
                b'\xff\x00' + struct.pack(b'>I', dev.serial))
            click.echo(
                'Using YubiKey serial as public ID: {}'.format(public_id))

    public_id = modhex_decode(public_id)

    if not private_id:
        if not force:
            private_id = click.prompt(
                'Enter private ID [blank to randomly generate]',
                default='',
                show_default=False)
        if force or private_id == '':
            private_id = os.urandom(6)
            click.echo(
                'Using a randomly generated private ID: {}'.format(
                    b2a_hex(private_id).decode('ascii')))
        else:
            private_id = a2b_hex(private_id)

    if not key:
        if not force:
            key = click.prompt(
                'Enter secret key [blank to randomly generate]',
                default='', show_default=False)
        if force or key == '':
            key = os.urandom(16)
            click.echo(
                'Using a randomly generated secret key: {}'.format(
                    b2a_hex(key).decode('ascii')))
        else:
            key = a2b_hex(key)

    force or click.confirm('Program an OTP credential in slot {}?'.format(slot),
                           abort=True)
    try:
        dev.driver.program_otp(slot, key, public_id, private_id, not no_enter)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@slot.command()
@click_slot_argument
@click.argument('password', required=False)
@click.option(
    '-g', '--generate', is_flag=True, help='Generate a random password.')
@click.option(
    '-l', '--length', type=click.IntRange(1, 38),
    help='Length of generated password.')
@click.option(
    '-k', '--keyboard-layout', type=click.Choice(
            [l.name for l in KEYBOARD_LAYOUT]),
    default='MODHEX', show_default=True,
    help='Keyboard layout to use for the static password.')
@click.option('--no-enter', is_flag=True, help="Don't send an Enter "
              'keystroke after outputting the password.')
@click_force_option
@click.pass_context
def static(
        ctx, slot, password, generate, length,
        keyboard_layout, no_enter, force):
    """
    Configure a static password.

    To avoid problems with different keyboard layouts, the following characters
    are allowed by default: cbdefghijklnrtuv

    Use the --keyboard-layout option to allow more characters based on
    preferred keyboard layout.
    """

    keyboard_layout = KEYBOARD_LAYOUT[keyboard_layout]

    if password and len(password) > 38:
        ctx.fail('Password too long (maximum length is 38 characters).')
    if generate and not length:
        ctx.fail('Provide a length for the generated password.')

    if not password and not generate:
        password = click.prompt('Enter a static password')
    elif not password and generate:
        password = generate_static_pw(length, keyboard_layout).decode()

    dev = ctx.obj['dev']

    if not force:
        _confirm_slot_overwrite(dev, slot)
    try:
        dev.driver.program_static(
            slot, password, not no_enter, keyboard_layout=keyboard_layout)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@slot.command()
@click_slot_argument
@click.argument('key', required=False)
@click.option(
    '-t', '--touch', is_flag=True, help='Require touch'
    ' on YubiKey to generate response.')
@click.option(
        '-T', '--totp', is_flag=True, required=False,
        help='Use a base32 encoded key for TOTP credentials.')
@click_force_option
@click.pass_context
def chalresp(ctx, slot, key, totp, touch, force):
    """
    Program a challenge-response credential.

    If key is not given, a randomly generated key will be used.
    """
    dev = ctx.obj['dev']

    if not key:
        if totp:
            while True:
                key = click.prompt('Enter a secret key (base32)')
                try:
                    key = parse_b32_key(key)
                    break
                except Exception as e:
                    click.echo(e)
                    pass
        else:
            key = click.prompt(
                'Enter a secret key [blank to randomly generate]',
                default='', show_default=False)
            if force or key == '':
                key = os.urandom(20)
                click.echo('Using a randomly generated key: {}'.format(
                    b2a_hex(key).decode('ascii')))
            else:
                key = parse_key(key)
    else:
        if totp:
            key = parse_b32_key(key)
        else:
            key = parse_key(key)

    cred_type = 'TOTP' if totp else 'challenge-response'
    force or click.confirm('Program a {} credential in slot {}?'
                           .format(cred_type, slot), abort=True)
    try:
        dev.driver.program_chalresp(slot, key, touch)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@slot.command()
@click_slot_argument
@click.argument('challenge', required=False)
@click.option(
    '-T', '--totp', is_flag=True, help='Generate a TOTP code, '
    'use the current time as challenge.')
@click.option(
    '-d', '--digits', type=click.Choice(['6', '8']), default='6',
    help='Number of digits in generated TOTP code (default is 6).')
@click.pass_context
def calculate(ctx, slot, challenge, totp, digits):
    """
    Perform a challenge-response operation.

    Send a challenge (in hex) to a YubiKey slot with a challenge-response
credential, and read the response. Supports output as a OATH-TOTP code.
    """
    dev = ctx.obj['dev']
    if not challenge and not totp:
        ctx.fail('No challenge provided.')

    # Check that slot is not empty
    slot1, slot2 = dev.driver.slot_status
    if (slot == 1 and not slot1) or (slot == 2 and not slot2):
        ctx.fail('Cannot perform challenge-response on an empty slot.')

    # Timestamp challenge should be int
    if challenge and totp:
        try:
            challenge = int(challenge)
        except Exception as e:
            logger.error('Error', exc_info=e)
            ctx.fail('Timestamp challenge for TOTP must be an integer.')
    try:
        res = dev.driver.calculate(
            slot, challenge, totp=totp,
            digits=int(digits), wait_for_touch=False)
    except YkpersError as e:
        # Touch is set
        if e.errno == 11:
            prompt_for_touch()
            try:
                res = dev.driver.calculate(
                    slot, challenge, totp=totp,
                    digits=int(digits), wait_for_touch=True)
            except YkpersError as e:
                # Touch timed out
                if e.errno == 4:
                    ctx.fail('The YubiKey timed out.')
                else:
                    ctx.fail(e)
        else:
            ctx.fail('Failed to calculate challenge.')
    click.echo(res)


@slot.command()
@click_slot_argument
@click.argument('key', callback=click_parse_b32_key, required=False)
@click.option('-d', '--digits', type=click.Choice(['6', '8']), default='6',
              help='Number of digits in generated code (default is 6).')
@click.option('-c', '--counter', type=int, default=0,
              help='Initial counter value.')
@click.option('--no-enter', is_flag=True, help="Don't send an Enter "
              'keystroke after outputting the code.')
@click_force_option
@click.pass_context
def hotp(ctx, slot, key, digits, counter, no_enter, force):
    """
    Program an HMAC-SHA1 OATH-HOTP credential.

    """
    dev = ctx.obj['dev']
    if not key:
        while True:
            key = click.prompt('Enter a secret key (base32)')
            try:
                key = parse_b32_key(key)
                break
            except Exception as e:
                click.echo(e)
                pass

    force or click.confirm(
        'Program a HOTP credential in slot {}?'.format(slot), abort=True)
    try:
        dev.driver.program_hotp(
            slot, key, counter, int(digits) == 8, not no_enter)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@slot.command()
@click_slot_argument
@click_force_option
@click.pass_context
@click.option(
    '--enter/--no-enter', default=True, show_default=True,
    help="Should send 'Enter' keystroke after slot output.")
@click.option(
    '-p', '--pacing', type=click.Choice(['0', '20', '40', '60']),
    default='0', show_default=True, help='Throttle output speed by '
    'adding a delay (in ms) between characters emitted.')
def settings(ctx, slot, enter, pacing, force):
    """
    Update the settings for a slot.

    Change the settings for a slot without changing the stored secret.
    All settings not specified will be written with default values.
    """
    dev = ctx.obj['dev']
    if not dev.driver.slot_status[slot - 1]:
        ctx.fail('Not possible to update settings on an empty slot.')
    force or click.confirm(
        'Update the settings for slot {}? '
        'All existing settings will be overwritten.'.format(slot), abort=True)
    click.echo('Updating settings for slot {}...'.format(slot))

    if pacing is not None:
        pacing = int(pacing)

    try:
        dev.driver.update_settings(slot, enter=enter, pacing=pacing)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


slot.transports = TRANSPORT.OTP
