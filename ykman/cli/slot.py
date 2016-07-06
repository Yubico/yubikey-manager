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

from .util import click_force_option, click_callback, click_skip_on_help
from ..util import TRANSPORT, modhex_decode, modhex_encode
from base64 import b32decode
from binascii import a2b_hex, b2a_hex
from ..driver_otp import YkpersError
import os
import re
import struct
import click


@click_callback()
def parse_key(ctx, param, val):
    val = val.upper()
    if re.match(r'^([0-9A-F]{2})+$', val):  # hex
        return a2b_hex(val)
    else:
        # Key should be b32 encoded
        val += '=' * (-len(val) % 8)  # Support unpadded
        return b32decode(val)


def parse_hex(length):
    @click_callback()
    def inner(ctx, param, val):
        val = a2b_hex(val)
        if len(val) != length:
            raise ValueError('Must be exactly {} bytes.'.format(length))
        return val
    return inner


@click_callback(invoke_on_missing=True)
def parse_public_id(ctx, param, value):
    if value is None:
        dev = ctx.obj['dev']
        if dev.serial is None:
            ctx.fail('Serial number not set, public-id must be provided')
        value = b'\xff\x00' + struct.pack(b'>I', dev.serial)
        click.echo('Using serial as public ID: {}'.format(modhex_encode(value)))
    else:
        value = modhex_decode(value)
    return value


click_slot_argument = click.argument('slot', type=click.Choice(['1', '2']),
                                     callback=lambda c, p, v: int(v))


def _failed_to_write_msg():
    click.echo('Failed to write to the device. Make sure the device does not '
               'have restricted access.')


@click.group()
@click.pass_context
@click_skip_on_help
@click.option('--access-code', required=False, metavar="HEX", callback=parse_hex(6),
              help='If your YubiKey is write-protected using an access code, '
              'you will need to specify it here for any operation that writes '
              'to the device.')
def slot(ctx, access_code):
    """
    Manage YubiKey OTP slots.

    The YubiKey provides two keyboard-based slots which can each be configured
    with a credential. Several credential types are supported.
    """
    ctx.obj['dev'].driver.access_code = access_code
slot.transports = TRANSPORT.OTP


@slot.command()
@click.pass_context
def info(ctx):
    """
    Display status of OTP slots.
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
    except YkpersError:
        _failed_to_write_msg()


@slot.command()
@click_slot_argument
@click_force_option
@click.pass_context
def delete(ctx, slot, force):
    """
    Deletes the configuration of a slot.
    """
    dev = ctx.obj['dev']
    force or click.confirm('Really delete slot {} or the YubiKey?'.format(slot),
                           abort=True)
    click.echo('Deleting slot: {}...'.format(slot))
    try:
        dev.driver.zap_slot(slot)
    except YkpersError:
        _failed_to_write_msg()


@slot.command()
@click_slot_argument
@click.option('-P', '--public-id', required=False, callback=parse_public_id,
              help='Static part of the OTP, defaults to the devices serial '
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
    Program a YubiKey OTP credential.

    If --public-id is not given, the devices serial number will be used.
    If --private-id is not given, a randomly generated one will be used.
    If --key is not given, a randomly generated key will be used.
    """
    dev = ctx.obj['dev']
    if not private_id:
        private_id = os.urandom(6)
        click.echo('Using a randomly generated private ID: {}'.format(
            b2a_hex(private_id).decode('ascii')))
    if not key:
        key = os.urandom(16)
        click.echo('Using a randomly generated secret key: {}'.format(
            b2a_hex(key).decode('ascii')))
    force or click.confirm('Program an OTP credential in slot {}?'.format(slot),
                           abort=True)
    try:
        dev.driver.program_otp(slot, key, public_id, private_id, not no_enter)
    except YkpersError:
        _failed_to_write_msg()


@slot.command()
@click_slot_argument
@click.argument('password')
@click.option('--no-enter', is_flag=True, help="Don't send an Enter "
              'keystroke after outputting the password.')
@click_force_option
@click.pass_context
def static(ctx, slot, password, no_enter, force):
    """
    Program a static password.
    """
    dev = ctx.obj['dev']
    force or click.confirm('Program a static password in slot {}?'.format(slot),
                           abort=True)
    click.echo('Setting static password in slot {}...'.format(slot))
    try:
        dev.driver.program_static(slot, password, not no_enter)
    except YkpersError:
        _failed_to_write_msg()


@slot.command()
@click_slot_argument
@click.option('-k', '--key', metavar='HEX', callback=parse_key, required=False,
              help='HMAC-SHA1 secret key.')
@click.option('--require-touch', is_flag=True, help='Require physical button '
              'press to generate response.')
@click_force_option
@click.pass_context
def chalresp(ctx, slot, key, require_touch, force):
    """
    Program a challenge-response credential.

    If --key is not given, a randomly generated key will be used.
    """
    dev = ctx.obj['dev']
    if not key:
        click.echo('Using a randomly generated key.')
        key = os.urandom(20)

    force or click.confirm('Program a challenge-response credential in slot {}?'
                           .format(slot), abort=True)

    click.echo('Programming challenge-response in slot {}...'.format(slot))
    try:
        dev.driver.program_chalresp(slot, key, require_touch)
    except YkpersError:
        _failed_to_write_msg()


@slot.command()
@click_slot_argument
@click.argument('key', callback=parse_key)
@click.option('--digits', type=click.Choice(['6', '8']), default='6',
              callback=lambda c, p, v: int(v),
              help='Number of digits to output for HOTP codes.')
@click.option('--imf', type=int, default=0,
              help='Initial moving factor for credential.')
@click.option('--no-enter', is_flag=True, help="Don't send an Enter "
              'keystroke after outputting an OTP.')
@click_force_option
@click.pass_context
def hotp(ctx, slot, key, digits, imf, no_enter, force):
    """
    Program an HMAC-SHA1 OATH-HOTP credential.

    KEY is given as a hex or base32 encoded string.
    """
    dev = ctx.obj['dev']
    force or click.confirm('Program a HOTP credential in slot {}?'.format(slot),
                           abort=True)
    click.echo('Programming HOTP credential in slot {}...'.format(slot))
    try:
        dev.driver.program_hotp(slot, key, imf, digits == 8, not no_enter)
    except YkpersError:
        _failed_to_write_msg()
