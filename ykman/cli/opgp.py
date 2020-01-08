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

import logging
import click
from ..util import TRANSPORT, parse_certificates, parse_private_key
from ..opgp import OpgpController, KEY_SLOT, TOUCH_MODE
from ..driver_ccid import APDUError, SW
from .util import (
    click_force_option, click_format_option, click_postpone_execution,
    EnumChoice)


logger = logging.getLogger(__name__)


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


@click.group()
@click.pass_context
@click_postpone_execution
def openpgp(ctx):
    """
    Manage OpenPGP Application.

    Examples:

    \b
      Set the retries for PIN, Reset Code and Admin PIN to 10:
      $ ykman openpgp set-retries 10 10 10

    \b
      Require touch to use the authentication key:
      $ ykman openpgp set-touch aut on
    """
    try:
        ctx.obj['controller'] = OpgpController(ctx.obj['dev'].driver)
    except APDUError as e:
        if e.sw == SW.NOT_FOUND:
            ctx.fail("The OpenPGP application can't be found on this "
                     'YubiKey.')
        logger.debug('Failed to load OpenPGP Application', exc_info=e)
        ctx.fail('Failed to load OpenPGP Application')


@openpgp.command()
@click.pass_context
def info(ctx):
    """
    Display status of OpenPGP application.
    """
    controller = ctx.obj['controller']
    click.echo('OpenPGP version: %d.%d' % controller.get_openpgp_version())
    click.echo('Application version: %d.%d.%d' % controller.version)
    click.echo()
    retries = controller.get_remaining_pin_tries()
    click.echo('PIN tries remaining: {}'.format(retries.pin))
    click.echo('Reset code tries remaining: {}'.format(retries.reset))
    click.echo('Admin PIN tries remaining: {}'.format(retries.admin))
    # Touch only available on YK4 and later
    if controller.version >= (4, 2, 6):
        click.echo()
        click.echo('Touch policies')
        click.echo(
            'Signature key           {!s}'.format(
                controller.get_touch(KEY_SLOT.SIG)))
        click.echo(
            'Encryption key          {!s}'.format(
                controller.get_touch(KEY_SLOT.ENC)))
        click.echo(
            'Authentication key      {!s}'.format(
                controller.get_touch(KEY_SLOT.AUT)))
        if controller.supports_attestation:
            click.echo(
                'Attestation key         {!s}'.format(
                    controller.get_touch(KEY_SLOT.ATT)))


@openpgp.command()
@click.confirmation_option('-f', '--force', prompt='WARNING! This will delete '
                           'all stored OpenPGP keys and data and restore '
                           'factory settings?')
@click.pass_context
def reset(ctx):
    """
    Reset OpenPGP application.

    This action will wipe all OpenPGP data, and set all PINs to their default
    values.
    """
    click.echo("Resetting OpenPGP data, don't remove your YubiKey...")
    ctx.obj['controller'].reset()
    click.echo('Success! All data has been cleared and default PINs are set.')
    echo_default_pins()


def echo_default_pins():
    click.echo('PIN:         123456')
    click.echo('Reset code:  NOT SET')
    click.echo('Admin PIN:   12345678')


@openpgp.command('set-touch')
@click.argument('key', metavar='KEY', type=EnumChoice(KEY_SLOT))
@click.argument('policy', metavar='POLICY', type=EnumChoice(TOUCH_MODE))
@click.option('-a', '--admin-pin', help='Admin PIN for OpenPGP.')
@click_force_option
@click.pass_context
def set_touch(ctx, key, policy, admin_pin, force):
    """
    Set touch policy for OpenPGP keys.

    \b
    KEY     Key slot to set (sig, enc, aut or att).
    POLICY  Touch policy to set (on, off, fixed, cached or cached-fixed).

    The touch policy is used to require user interaction for all
    operations using the private key on the YubiKey. The touch policy is set
    indivdually for each key slot. To see the current touch policy, run

    \b
        $ ykman openpgp info

    Touch policies:

    \b
    Off (default)   No touch required
    On              Touch required
    Fixed           Touch required, can't be disabled without a full reset
    Cached          Touch required, cached for 15s after use
    Cached-Fixed    Touch required, cached for 15s after use, can't be disabled
                    without a full reset
    """
    controller = ctx.obj['controller']

    policy_name = policy.name.lower().replace('_', '-')

    if policy not in controller.supported_touch_policies:
        ctx.fail('Touch policy {} not supported by this YubiKey.'
                 .format(policy_name))

    if key == KEY_SLOT.ATT and not controller.supports_attestation:
        ctx.fail('Attestation is not supported by this YubiKey.')

    if admin_pin is None:
        admin_pin = click.prompt('Enter admin PIN', hide_input=True, err=True)

    if force or click.confirm(
        'Set touch policy of {} key to {}?'.format(
            key.value.lower(),
            policy_name),
            abort=True, err=True):
        try:
            controller.verify_admin(admin_pin)
            controller.set_touch(key, policy)
        except APDUError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                ctx.fail('Touch policy not allowed.')
            logger.debug('Failed to set touch policy', exc_info=e)
            ctx.fail('Failed to set touch policy.')


@openpgp.command('set-pin-retries')
@click.argument(
    'pin-retries', type=click.IntRange(1, 99), metavar='PIN-RETRIES')
@click.argument(
    'reset-code-retries',
    type=click.IntRange(1, 99), metavar='RESET-CODE-RETRIES')
@click.argument(
    'admin-pin-retries',
    type=click.IntRange(1, 99), metavar='ADMIN-PIN-RETRIES')
@click.option('-a', '--admin-pin', help='Admin PIN for OpenPGP.')
@click_force_option
@click.pass_context
def set_pin_retries(
        ctx, admin_pin, pin_retries,
        reset_code_retries, admin_pin_retries, force):
    """
    Set PIN, Reset Code and Admin PIN retries.
    """
    controller = ctx.obj['controller']

    if admin_pin is None:
        admin_pin = click.prompt('Enter admin PIN', hide_input=True, err=True)

    resets_pins = controller.version < (4, 0, 0)
    if resets_pins:
        click.echo('WARNING: Setting PIN retries will reset the values for all '
                   '3 PINs!')
    if force or click.confirm(
            'Set PIN retry counters to: {} {} {}?'.format(
                pin_retries, reset_code_retries,
                admin_pin_retries), abort=True, err=True):

        controller.verify_admin(admin_pin)
        controller.set_pin_retries(
            pin_retries, reset_code_retries, admin_pin_retries)

        if resets_pins:
            click.echo('Default PINs are set.')
            echo_default_pins()


@openpgp.command()
@click.pass_context
@click.option('-P', '--pin', help='PIN code.')
@click_format_option
@click.argument('key', metavar='KEY', type=EnumChoice(KEY_SLOT))
@click.argument('certificate', type=click.File('wb'), metavar='CERTIFICATE')
def attest(ctx, key, certificate, pin, format):
    """
    Generate a attestation certificate for a key.

    Attestation is used to show that an asymmetric key was generated on the
    YubiKey and therefore doesn't exist outside the device.

    \b
    KEY         Key slot to attest (sig, enc, aut).
    CERTIFICATE File to write attestation certificate to. Use '-' to use stdout.
    """

    controller = ctx.obj['controller']

    if not pin:
        pin = click.prompt(
            'Enter PIN', default='', hide_input=True,
            show_default=False, err=True)

    try:
        cert = controller.read_certificate(key)
    except ValueError:
        cert = None

    if not cert or click.confirm(
            'There is already data stored in the certificate slot for {}, '
            'do you want to overwrite it?'.format(key.value)):
        touch_policy = controller.get_touch(KEY_SLOT.ATT)
        if touch_policy in [TOUCH_MODE.ON, TOUCH_MODE.FIXED]:
            click.echo('Touch your YubiKey...')
        try:
            controller.verify_pin(pin)
            cert = controller.attest(key)
            certificate.write(cert.public_bytes(encoding=format))
        except Exception as e:
            logger.debug('Failed to attest', exc_info=e)
            ctx.fail('Attestation failed')


@openpgp.command('export-certificate')
@click.pass_context
@click.argument('key', metavar='KEY', type=EnumChoice(KEY_SLOT))
@click_format_option
@click.argument('certificate', type=click.File('wb'), metavar='CERTIFICATE')
def export_certificate(ctx, key, format, certificate):
    """
    Export an OpenPGP certificate.

    \b
    KEY         Key slot to read from (sig, enc, aut, or att).
    CERTIFICATE File to write certificate to. Use '-' to use stdout.
    """
    controller = ctx.obj['controller']
    try:
        cert = controller.read_certificate(key)
    except ValueError:
        ctx.fail('Failed to read certificate from {}'.format(key.name))
    certificate.write(cert.public_bytes(encoding=format))


@openpgp.command('delete-certificate')
@click.option('-a', '--admin-pin', help='Admin PIN for OpenPGP.')
@click.pass_context
@click.argument('key', metavar='KEY', type=EnumChoice(KEY_SLOT))
def delete_certificate(ctx, key, admin_pin):
    """
    Delete an OpenPGP certificate.

    \b
    KEY         Key slot to delete certificate from (sig, enc, aut, or att).
    """
    controller = ctx.obj['controller']
    if admin_pin is None:
        admin_pin = click.prompt('Enter admin PIN', hide_input=True, err=True)
    try:
        controller.verify_admin(admin_pin)
        controller.delete_certificate(key)
    except Exception as e:
        logger.debug('Failed to delete ', exc_info=e)
        ctx.fail('Failed to delete certificate.')


@openpgp.command('import-certificate')
@click.option('-a', '--admin-pin', help='Admin PIN for OpenPGP.')
@click.pass_context
@click.argument('key', metavar='KEY', type=EnumChoice(KEY_SLOT))
@click.argument('cert', type=click.File('rb'), metavar='CERTIFICATE')
def import_certificate(ctx, key, cert, admin_pin):
    """
    Import an OpenPGP certificate.

    \b
    KEY         Key slot to import certificate to (sig, enc, aut, or att).
    CERTIFICATE File containing the certificate. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']

    if admin_pin is None:
        admin_pin = click.prompt('Enter admin PIN', hide_input=True, err=True)

    try:
        certs = parse_certificates(cert.read(), password=None)
    except Exception as e:
        logger.debug('Failed to parse', exc_info=e)
        ctx.fail('Failed to parse certificate.')
    if len(certs) != 1:
        ctx.fail('Can only import one certificate.')
    try:
        controller.verify_admin(admin_pin)
        controller.import_certificate(key, certs[0])
    except Exception as e:
        logger.debug('Failed to import', exc_info=e)
        ctx.fail('Failed to import certificate')


@openpgp.command('import-attestation-key')
@click.option('-a', '--admin-pin', help='Admin PIN for OpenPGP.')
@click.pass_context
@click.argument('private-key', type=click.File('rb'), metavar='PRIVATE-KEY')
def import_attestation_key(ctx, private_key, admin_pin):
    """
    Import a private attestation key.

    Import a private key for OpenPGP attestation.

    \b
    PRIVATE-KEY File containing the private key. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']

    if admin_pin is None:
        admin_pin = click.prompt('Enter admin PIN', hide_input=True, err=True)
    try:
        private_key = parse_private_key(private_key.read(), password=None)
    except Exception as e:
        logger.debug('Failed to parse', exc_info=e)
        ctx.fail('Failed to parse private key.')
    try:
        controller.verify_admin(admin_pin)
        controller.import_key(KEY_SLOT.ATT, private_key)
    except Exception as e:
        logger.debug('Failed to import', exc_info=e)
        ctx.fail('Failed to import attestation key.')


openpgp.transports = TRANSPORT.CCID
