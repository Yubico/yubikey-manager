# Copyright (c) 2017 Yubico AB
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

from ..util import TRANSPORT
from ..piv import PivController, ALGO, OBJ, SW, SLOT, PIN_POLICY, TOUCH_POLICY
from ..driver_ccid import APDUError, SW_APPLICATION_NOT_FOUND
from .util import click_skip_on_help, click_callback
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from binascii import b2a_hex, a2b_hex
import click


def one_of(data):
    def inner(ctx, param, key):
        if key is not None:
            return data[key]
    return inner


def get_or_fail(data):
    def inner(key):
        if key in data:
            return data[key]
        raise ValueError('Invalid value: {}. Must be one of: {}'.format(
            key, ', '.join(data.keys())))
    return inner


def int_in_range(minval, maxval):
    def inner(val):
        intval = int(val)
        if minval <= intval <= maxval:
            return intval
        raise ValueError('Invalid value: {}. Must be in range {}-{}'.format(
            intval, minval, maxval))
    return inner


@click_callback()
def click_parse_piv_slot(ctx, param, val):
    try:
        return SLOT(int(val, 16))
    except:
        raise ValueError(val)


click_slot_argument = click.argument('slot', callback=click_parse_piv_slot)
click_management_key_option = click.option(
    '-m', '--management-key',
    help='A management key is required for administrative tasks.')


@click.group()
@click.pass_context
@click_skip_on_help
def piv(ctx):
    """
    Manage YubiKey PIV functions.
    """
    try:
        controller = PivController(ctx.obj['dev'].driver)
        ctx.obj['controller'] = controller
    except APDUError as e:
        if e.sw == SW_APPLICATION_NOT_FOUND:
            ctx.fail("The applet can't be found on the device.")
        raise


@piv.command()
@click.pass_context
def info(ctx):
    """
    Display status of PIV functionality.
    """
    controller = ctx.obj['controller']
    click.echo('PIV version: %d.%d.%d' % controller.version)
    click.echo('PIN tries remaining: %d' % controller.get_pin_tries())

    try:
        chuid = b2a_hex(controller.get_data(OBJ.CHUID)).decode()
    except APDUError as e:
        if e.sw == SW.NOT_FOUND:
            chuid = 'No data available.'
    click.echo('CHUID:\t' + chuid)

    try:
        ccc = b2a_hex(controller.get_data(OBJ.CAPABILITY)).decode()
    except APDUError as e:
        if e.sw == SW.NOT_FOUND:
            ccc = 'No data available.'
    click.echo('CCC: \t' + ccc)

    for (slot, cert) in controller.list_certificates().items():
        click.echo('Slot %02x:' % slot)
        click.echo('\tAlgorithm:\t%s' % ALGO.from_public_key(cert.public_key())
                   .name)
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = cn[0].value if len(cn) > 0 else 'None'
        click.echo('\tSubject CN:\t%s' % cn)
        cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = cn[0].value if len(cn) > 0 else 'None'
        click.echo('\tIssuer CN:\t%s' % cn)
        click.echo('\tFingerprint:\t%s' % b2a_hex(
            cert.fingerprint(hashes.SHA256())).decode('ascii'))
        click.echo('\tNot before:\t%s' % cert.not_valid_before)
        click.echo('\tNot after:\t%s' % cert.not_valid_after)


@piv.command()
@click.pass_context
@click.confirmation_option(
    '-f', '--force', prompt='WARNING! This will delete '
    'all stored PIV data and restore factory settings. Proceed?')
def reset(ctx):
    """
    Reset all PIV data.

    This action will wipe all credentials and reset factory settings for
    the PIV functionality on the device.
    """

    click.echo('Resetting PIV data...')
    ctx.obj['controller'].reset()
    click.echo(
        'Success! All credentials have been cleared from the device.')
    click.echo('Your YubiKey now has the default PIN, PUK and Management Key:')
    click.echo('\tPIN:\t123456')
    click.echo('\tPUK:\t12345678')
    click.echo(
        '\tManagement Key:\t010203040506070801020304050607080102030405060708')


@piv.command()
@click.pass_context
@click_slot_argument
@click_management_key_option
@click.option(
    '-a', '--algorithm', help='Algorithm to use in key generation.',
    type=click.Choice(
        ['RSA1024', 'RSA2048', 'ECCP256', 'ECCP384']), default='RSA2048')
@click.option(
    '-f', '--key-format', type=click.Choice(['PEM', 'DER']),
    default='PEM', help='Key serialization format.')
@click.option(
    '-p', '--pin-policy',
    type=click.Choice(['DEFAULT', 'NEVER', 'ONCE', 'ALWAYS']),
    default='DEFFAULT',
    help='PIN policy for slot where keypair is generated.')
@click.option(
    '-t', '--touch-policy',
    type=click.Choice(['DEFAULT', 'NEVER', 'ALWAYS', 'CACHED']),
    default='DEFAULT',
    help='Touch policy for slot where keypair is generated.')
def generate(
    ctx, slot, management_key, algorithm, key_format, touch_policy,
        pin_policy):
    """
    Generate a keypair in one of the slots.
    """
    controller = ctx.obj['controller']
    if not management_key:
        management_key = click.prompt(
            'Enter a management key', default='', show_default=False)
    controller.authenticate(a2b_hex(management_key))
    public_key = controller.generate_key(
        slot,
        ALGO.from_string(algorithm),
        PIN_POLICY.from_string(pin_policy),
        TOUCH_POLICY.from_string(touch_policy))
    key_encoding = serialization.Encoding.PEM \
        if key_format == 'PEM' else serialization.Encoding.DER
    public_key_serialised = public_key.public_bytes(
            encoding=key_encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    click.echo(public_key_serialised)


piv.transports = TRANSPORT.CCID
