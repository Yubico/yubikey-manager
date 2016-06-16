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

from ..util import TRANSPORT, modhex_decode, modhex_encode
from .util import click_force_option
from base64 import b32decode
from binascii import a2b_hex
import os
import re
import struct
import click


def parse_key(ctx, param, val):
    if val is None:
        return None
    val = val.upper()
    if re.match(r'^([0-9A-F]{2})+$', val):  # hex
        return a2b_hex(val)
    else:
        # Key should be b32 encoded
        val += '=' * (-len(val) % 8)  # Support unpadded
        try:
            return b32decode(val)
        except TypeError as e:
            raise ValueError('{}'.format(e))


def parse_public_id(ctx, param, value):
    if value is None:
        dev = ctx.obj['dev']
        if dev.serial is None:
            ctx.fail('serial number not set, public-id must be provided')
        value = b'\xff\x00' + struct.pack(b'>I', dev.serial)
        click.echo('Using serial as public ID: {}'.format(modhex_encode(value)))
    else:
        value = modhex_decode(value)
    return value


click_slot_argument = click.argument('slot', type=click.Choice(['1', '2']),
                                     callback=lambda c, p, v: int(v))


@click.group()
def slot():
    """
    Manage YubiKey OTP slots.
    """
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
    Swaps the two slot configurations with each other.
    """
    dev = ctx.obj['dev']
    click.echo('Swapping slots...')
    dev.driver.swap_slots()


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
    dev.driver.zap_slot(slot)


@slot.command()
@click_slot_argument
@click.argument('key', callback=parse_key)
@click.option('--public-id', required=False, callback=parse_public_id,
              help='Static part of the OTP, defaults to the devices serial '
              'number converted to modhex.', metavar='MODHEX')
@click.option('--private-id', required=False, default='00'*6,
              callback=lambda c, p, v: a2b_hex(v), help='6 byte private '
              'identifier of the credential.', metavar='HEX')
@click.option('--no-enter', is_flag=True, help="Don't send an Enter "
              'keystroke after outputting an OTP.')
@click_force_option
@click.pass_context
def otp(ctx, slot, key, public_id, private_id, no_enter, force):
    """
    Program a YubiKey OTP credential.

    KEY is a 16 byte AES key given as a hex encoded string.
    """
    dev = ctx.obj['dev']
    force or click.confirm('Program an OTP credential in slot {}?'.format(slot),
                           abort=True)
    dev.driver.program_otp(slot, key, public_id, private_id, not no_enter)


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
    dev.driver.program_static(slot, password, not no_enter)


@slot.command()
@click_slot_argument
@click.argument('key', callback=parse_key, required=False)
@click.option('--require-touch', is_flag=True, help='Require physical button '
              'press to generate response.')
@click_force_option
@click.pass_context
def chalresp(ctx, slot, key, require_touch, force):
    """
    Program an HMAC-SHA1 challenge-response credential.

    KEY is given as a hex encoded string.
    If KEY is not given, a randomly generated key will be used.
    """
    dev = ctx.obj['dev']
    if not key:
        click.echo('Using a randomly generated key.')
        key = os.urandom(20)

    force or click.confirm('Program a challenge-response credential in slot {}?'
                           .format(slot), abort=True)

    click.echo('Programming challenge-response in slot {}...'.format(slot))
    dev.driver.program_chalresp(slot, key, require_touch)


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
    dev.driver.program_hotp(slot, key, imf, digits == 8, not no_enter)
