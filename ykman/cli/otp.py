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
    click_postpone_execution, prompt_for_touch, EnumChoice)
from ..util import (
    TRANSPORT, generate_static_pw, modhex_decode,
    modhex_encode, parse_key, parse_b32_key)
from binascii import a2b_hex, b2a_hex
from .. import __version__
from ..driver_otp import YkpersError
from ..otp import OtpController, PrepareUploadFailed, SlotConfig
from ..scancodes import KEYBOARD_LAYOUT
import logging
import os
import struct
import click
import webbrowser


logger = logging.getLogger(__name__)


def parse_hex(length):
    @click_callback()
    def inner(ctx, param, val):
        val = a2b_hex(val)
        if len(val) != length:
            raise ValueError('Must be exactly {} bytes.'.format(length))
        return val
    return inner


def parse_access_code_hex(access_code_hex):
    try:
        access_code = a2b_hex(access_code_hex)
    except TypeError as e:
        raise ValueError(e)
    if len(access_code) != 6:
        raise ValueError('Must be exactly 6 bytes.')

    return access_code


click_slot_argument = click.argument('slot', type=click.Choice(['1', '2']),
                                     callback=lambda c, p, v: int(v))


def _failed_to_write_msg(ctx, exc_info):
    logger.error('Failed to write to device', exc_info=exc_info)
    ctx.fail('Failed to write to the YubiKey. Make sure the device does not '
             'have restricted access.')


def _confirm_slot_overwrite(controller, slot):
    slot1, slot2 = controller.slot_status
    if slot == 1 and slot1:
        click.confirm(
            'Slot 1 is already configured. Overwrite configuration?',
            abort=True, err=True)
    if slot == 2 and slot2:
        click.confirm(
            'Slot 2 is already configured. Overwrite configuration?',
            abort=True, err=True)


@click.group()
@click.pass_context
@click_postpone_execution
@click.option(
    '--access-code', required=False, metavar='HEX',
    help='A 6 byte access code. Set to empty to use a prompt for input.')
def otp(ctx, access_code):
    """
    Manage OTP Application.

    The YubiKey provides two keyboard-based slots which can each be configured
    with a credential. Several credential types are supported.

    A slot configuration may be write-protected with an access code. This
    prevents the configuration to be overwritten without the access code
    provided. Mode switching the YubiKey is not possible when a slot is
    configured with an access code.

    Examples:

    \b
      Swap the configurations between the two slots:
      $ ykman otp swap

    \b
      Program a random challenge-response credential to slot 2:
      $ ykman otp chalresp --generate 2

    \b
      Program a Yubico OTP credential to slot 1, using the serial as public id:
      $ ykman otp yubiotp 1 --serial-public-id

    \b
      Program a random 38 characters long static password to slot 2:
      $ ykman otp static --generate 2 --length 38
    """

    ctx.obj['controller'] = OtpController(ctx.obj['dev'].driver)
    if access_code is not None:
        if access_code == '':
            access_code = click.prompt(
                'Enter access code', show_default=False, err=True)

        try:
            access_code = parse_access_code_hex(access_code)
        except Exception as e:
            ctx.fail('Failed to parse access code: ' + str(e))

    ctx.obj['controller'].access_code = access_code


@otp.command()
@click.pass_context
def info(ctx):
    """
    Display status of YubiKey Slots.
    """
    dev = ctx.obj['dev']
    controller = ctx.obj['controller']
    slot1, slot2 = controller.slot_status

    click.echo('Slot 1: {}'.format(slot1 and 'programmed' or 'empty'))
    click.echo('Slot 2: {}'.format(slot2 and 'programmed' or 'empty'))

    if dev.is_fips:
        click.echo('FIPS Approved Mode: {}'.format(
            'Yes' if controller.is_in_fips_mode else 'No'))


@otp.command()
@click.confirmation_option('-f', '--force', prompt='Swap the two slots of the '
                           'YubiKey?')
@click.pass_context
def swap(ctx):
    """
    Swaps the two slot configurations.
    """
    controller = ctx.obj['controller']
    click.echo('Swapping slots...')
    try:
        controller.swap_slots()
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.pass_context
@click.option(
    '-p', '--prefix', help='Added before the NDEF payload. Typically a URI.')
def ndef(ctx, slot, prefix):
    """
    Select slot configuration to use for NDEF.

    The default prefix will be used if no prefix is specified.
    """
    dev = ctx.obj['dev']
    controller = ctx.obj['controller']
    if not dev.config.nfc_supported:
        ctx.fail('NFC interface not available.')

    if not controller.slot_status[slot - 1]:
        ctx.fail('Slot {} is empty.'.format(slot))

    try:
        if prefix:
            controller.configure_ndef_slot(slot, prefix)
        else:
            controller.configure_ndef_slot(slot)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click_force_option
@click.pass_context
def delete(ctx, slot, force):
    """
    Deletes the configuration of a slot.
    """
    controller = ctx.obj['controller']
    if not force and not controller.slot_status[slot - 1]:
        ctx.fail('Not possible to delete an empty slot.')
    force or click.confirm(
        'Do you really want to delete'
        ' the configuration of slot {}?'.format(slot), abort=True, err=True)
    click.echo('Deleting the configuration of slot {}...'.format(slot))
    try:
        controller.zap_slot(slot)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.option('-P', '--public-id', required=False,
              help='Public identifier prefix.', metavar='MODHEX')
@click.option('-p', '--private-id', required=False, metavar='HEX',
              callback=parse_hex(6), help='6 byte private identifier.')
@click.option('-k', '--key', required=False, metavar='HEX',
              callback=parse_hex(16), help='16 byte secret key.')
@click.option('--no-enter', is_flag=True, help="Don't send an Enter "
              'keystroke after emitting the OTP.')
@click.option(
    '-S', '--serial-public-id', is_flag=True, required=False,
    help='Use YubiKey serial number as public ID. Conflicts with --public-id.')
@click.option(
    '-g', '--generate-private-id', is_flag=True, required=False,
    help='Generate a random private ID. Conflicts with --private-id.')
@click.option(
    '-G', '--generate-key', is_flag=True, required=False,
    help='Generate a random secret key. Conflicts with --key.')
@click.option(
    '-u', '--upload', is_flag=True, required=False,
    help='Upload credential to YubiCloud (opens in browser). '
    'Conflicts with --force.')
@click_force_option
@click.pass_context
def yubiotp(ctx, slot, public_id, private_id, key, no_enter, force,
            serial_public_id, generate_private_id,
            generate_key, upload):
    """
    Program a Yubico OTP credential.

    """

    dev = ctx.obj['dev']
    controller = ctx.obj['controller']

    if public_id and serial_public_id:
        ctx.fail('Invalid options: --public-id conflicts with '
                 '--serial-public-id.')

    if private_id and generate_private_id:
        ctx.fail('Invalid options: --private-id conflicts with '
                 '--generate-public-id.')

    if upload and force:
        ctx.fail('Invalid options: --upload conflicts with --force.')

    if key and generate_key:
        ctx.fail('Invalid options: --key conflicts with --generate-key.')

    if not public_id:
        if serial_public_id:
            if dev.serial is None:
                ctx.fail('Serial number not set, public ID must be provided')
            public_id = modhex_encode(
                b'\xff\x00' + struct.pack(b'>I', dev.serial))
            click.echo(
                'Using YubiKey serial as public ID: {}'.format(public_id))
        elif force:
            ctx.fail(
                'Public ID not given. Please remove the --force flag, or '
                'add the --serial-public-id flag or --public-id option.')
        else:
            public_id = click.prompt('Enter public ID', err=True)

    try:
        public_id = modhex_decode(public_id)
    except KeyError:
        ctx.fail('Invalid public ID, must be modhex.')

    if not private_id:
        if generate_private_id:
            private_id = os.urandom(6)
            click.echo(
                'Using a randomly generated private ID: {}'.format(
                    b2a_hex(private_id).decode('ascii')))
        elif force:
            ctx.fail(
                'Private ID not given. Please remove the --force flag, or '
                'add the --generate-private-id flag or --private-id option.')
        else:
            private_id = click.prompt('Enter private ID', err=True)
            private_id = a2b_hex(private_id)

    if not key:
        if generate_key:
            key = os.urandom(16)
            click.echo(
                'Using a randomly generated secret key: {}'.format(
                    b2a_hex(key).decode('ascii')))
        elif force:
            ctx.fail('Secret key not given. Please remove the --force flag, or '
                     'add the --generate-key flag or --key option.')
        else:
            key = click.prompt('Enter secret key', err=True)
            key = a2b_hex(key)

    if not upload and not force:
        upload = click.confirm('Upload credential to YubiCloud?',
                               abort=False, err=True)
    if upload:
        try:
            upload_url = controller.prepare_upload_key(
                key, public_id, private_id, serial=dev.serial,
                user_agent='ykman/' + __version__)
            click.echo('Upload to YubiCloud initiated successfully.')
        except PrepareUploadFailed as e:
            error_msg = '\n'.join(e.messages())
            ctx.fail('Upload to YubiCloud failed.\n' + error_msg)

    force or click.confirm('Program an OTP credential in slot {}?'.format(slot),
                           abort=True, err=True)

    try:
        controller.program_otp(slot, key, public_id, private_id, SlotConfig(
            append_cr=not no_enter
        ))
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)

    if upload:
        click.echo('Opening upload form in browser: ' + upload_url)
        webbrowser.open_new_tab(upload_url)


@otp.command()
@click_slot_argument
@click.argument('password', required=False)
@click.option(
    '-g', '--generate', is_flag=True, help='Generate a random password.')
@click.option(
    '-l', '--length', type=click.IntRange(1, 38),
    help='Length of generated password.')
@click.option(
    '-k', '--keyboard-layout', type=EnumChoice(KEYBOARD_LAYOUT),
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

    controller = ctx.obj['controller']

    if password and len(password) > 38:
        ctx.fail('Password too long (maximum length is 38 characters).')
    if generate and not length:
        ctx.fail('Provide a length for the generated password.')

    if not password and not generate:
        password = click.prompt('Enter a static password', err=True)
    elif not password and generate:
        password = generate_static_pw(length, keyboard_layout)

    if not force:
        _confirm_slot_overwrite(controller, slot)
    try:
        controller.program_static(slot, password, keyboard_layout, SlotConfig(
            append_cr=not no_enter
        ))
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click.argument('key', required=False)
@click.option(
    '-t', '--touch', is_flag=True, help='Require touch'
    ' on YubiKey to generate response.')
@click.option(
        '-T', '--totp', is_flag=True, required=False,
        help='Use a base32 encoded key for TOTP credentials.')
@click.option(
        '-g', '--generate', is_flag=True, required=False,
        help='Generate a random secret key. Conflicts with KEY argument.')
@click_force_option
@click.pass_context
def chalresp(ctx, slot, key, totp, touch, force, generate):
    """
    Program a challenge-response credential.

    If KEY is not given, an interactive prompt will ask for it.
    """
    controller = ctx.obj['controller']

    if key:
        if generate:
            ctx.fail('Invalid options: --generate conflicts with KEY argument.')
        elif totp:
            key = parse_b32_key(key)
        else:
            key = parse_key(key)
    else:
        if force and not generate:
            ctx.fail('No secret key given. Please remove the --force flag, '
                     'set the KEY argument or set the --generate flag.')
        elif totp:
            while True:
                key = click.prompt('Enter a secret key (base32)', err=True)
                try:
                    key = parse_b32_key(key)
                    break
                except Exception as e:
                    click.echo(e)
        else:
            if generate:
                key = os.urandom(20)
                click.echo('Using a randomly generated key: {}'.format(
                    b2a_hex(key).decode('ascii')))
            else:
                key = click.prompt('Enter a secret key', err=True)
                key = parse_key(key)

    cred_type = 'TOTP' if totp else 'challenge-response'
    force or click.confirm('Program a {} credential in slot {}?'
                           .format(cred_type, slot), abort=True, err=True)
    try:
        controller.program_chalresp(slot, key, touch)
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
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
    controller = ctx.obj['controller']
    if not challenge and not totp:
        ctx.fail('No challenge provided.')

    # Check that slot is not empty
    slot1, slot2 = controller.slot_status
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
        res = controller.calculate(
            slot, challenge, totp=totp,
            digits=int(digits), wait_for_touch=False)
    except YkpersError as e:
        # Touch is set
        if e.errno == 11:
            prompt_for_touch()
            try:
                res = controller.calculate(
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


@otp.command()
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
    controller = ctx.obj['controller']
    if not key:
        while True:
            key = click.prompt('Enter a secret key (base32)', err=True)
            try:
                key = parse_b32_key(key)
                break
            except Exception as e:
                click.echo(e)

    force or click.confirm(
        'Program a HOTP credential in slot {}?'.format(slot), abort=True,
        err=True)
    try:
        controller.program_hotp(
            slot, key, counter, int(digits) == 8, SlotConfig(
                append_cr=not no_enter
            ))
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)


@otp.command()
@click_slot_argument
@click_force_option
@click.pass_context
@click.option(
    '-A', '--new-access-code', metavar='HEX', required=False,
    help='Set a new 6 byte access code for the slot. Set to empty to use a '
         'prompt for input.')
@click.option(
    '--delete-access-code', is_flag=True,
    help='Remove access code from the slot.')
@click.option(
    '--enter/--no-enter', default=True, show_default=True,
    help="Should send 'Enter' keystroke after slot output.")
@click.option(
    '-p', '--pacing', type=click.Choice(['0', '20', '40', '60']),
    default='0', show_default=True, help='Throttle output speed by '
    'adding a delay (in ms) between characters emitted.')
@click.option('--use-numeric-keypad', is_flag=True, show_default=True,
              help='Use scancodes for numeric keypad when sending digits.'
              ' Helps with some keyboard layouts. ')
def settings(ctx, slot, new_access_code, delete_access_code, enter, pacing,
             use_numeric_keypad, force):
    """
    Update the settings for a slot.

    Change the settings for a slot without changing the stored secret.
    All settings not specified will be written with default values.
    """
    controller = ctx.obj['controller']

    if (new_access_code is not None) and delete_access_code:
        ctx.fail('--new-access-code conflicts with --delete-access-code.')

    if not controller.slot_status[slot - 1]:
        ctx.fail('Not possible to update settings on an empty slot.')

    if new_access_code is not None:
        if new_access_code == '':
            new_access_code = click.prompt(
                'Enter new access code', show_default=False, err=True)

        try:
            new_access_code = parse_access_code_hex(new_access_code)
        except Exception as e:
            ctx.fail('Failed to parse access code: ' + str(e))

    force or click.confirm(
        'Update the settings for slot {}? '
        'All existing settings will be overwritten.'.format(slot), abort=True,
        err=True)
    click.echo('Updating settings for slot {}...'.format(slot))

    if pacing is not None:
        pacing = int(pacing)

    try:
        controller.update_settings(slot, SlotConfig(
            append_cr=enter,
            pacing=pacing,
            numeric_keypad=use_numeric_keypad
        ))
    except YkpersError as e:
        _failed_to_write_msg(ctx, e)

    if new_access_code:
        try:
            controller.set_access_code(slot, new_access_code)
        except Exception as e:
            logger.error('Failed to set access code', exc_info=e)
            ctx.fail('Failed to set access code: ' + str(e))

    if delete_access_code:
        try:
            controller.delete_access_code(slot)
        except Exception as e:
            logger.error('Failed to delete access code', exc_info=e)
            ctx.fail('Failed to delete access code: ' + str(e))


otp.transports = TRANSPORT.OTP
