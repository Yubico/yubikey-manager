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

from ..util import TRANSPORT, parse_private_key, parse_certificate
from ..piv import (
    PivController, ALGO, OBJ, SW, SLOT, PIN_POLICY, TOUCH_POLICY,
    DEFAULT_MANAGEMENT_KEY, generate_random_management_key)
from ..driver_ccid import APDUError, SW_APPLICATION_NOT_FOUND
from .util import (
    click_force_option, click_skip_on_help, click_callback, prompt_for_touch,
    UpperCaseChoice)
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from binascii import b2a_hex, a2b_hex
import click
import datetime
import logging


logger = logging.getLogger(__name__)


@click_callback()
def click_parse_piv_slot(ctx, param, val):
    try:
        return SLOT(int(val, 16))
    except Exception:
        raise ValueError(val)


@click_callback()
def click_parse_format(ctx, param, val):
    if val == 'PEM':
        return serialization.Encoding.PEM
    elif val == 'DER':
        return serialization.Encoding.DER
    else:
        raise ValueError(val)


@click_callback()
def click_parse_management_key(ctx, param, val):
    try:
        key = a2b_hex(val)
        if key and len(key) != 24:
            return ValueError('Management key must be exactly 24 bytes '
                              '(48 hexadecimal digits) long.')
        return key
    except Exception:
        return ValueError(val)


click_slot_argument = click.argument('slot', callback=click_parse_piv_slot)
click_management_key_option = click.option(
    '-m', '--management-key',
    help='The management key.',
    callback=click_parse_management_key)
click_pin_option = click.option(
    '-P', '--pin', help='PIN code.')
click_format_option = click.option(
    '-F', '--format',
    type=UpperCaseChoice(['PEM', 'DER']), default='PEM', show_default=True,
    help='Encoding format.', callback=click_parse_format)
click_pin_policy_option = click.option(
    '--pin-policy',
    type=UpperCaseChoice(['DEFAULT', 'NEVER', 'ONCE', 'ALWAYS']),
    help='PIN policy for slot.')
click_touch_policy_option = click.option(
    '--touch-policy', type=UpperCaseChoice(
        ['DEFAULT', 'NEVER', 'ALWAYS', 'CACHED']),
    help='Touch policy for slot.')


@click.group()
@click.pass_context
@click_skip_on_help
def piv(ctx):
    """
    Manage PIV application.
    """
    try:
        controller = PivController(ctx.obj['dev'].driver)
        ctx.obj['controller'] = controller
    except APDUError as e:
        if e.sw == SW_APPLICATION_NOT_FOUND:
            ctx.fail("The PIV application can't be found on this YubiKey.")
        raise


@piv.command()
@click.pass_context
def info(ctx):
    """
    Display status of PIV application.
    """
    controller = ctx.obj['controller']
    click.echo('PIV version: %d.%d.%d' % controller.version)

    # Largest possible number of PIN tries to get back is 15
    tries = controller.get_pin_tries()
    tries = '15 or more.' if tries == 15 else tries
    click.echo('PIN tries remaining: %s' % tries)
    if controller.puk_blocked:
        click.echo('PUK blocked.')
    if controller.has_derived_key:
        click.echo('Management key is derived from PIN.')
    if controller.has_stored_key:
        click.echo('Management key is stored on the YubiKey, protected by PIN.')
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

    This action will wipe all data and restore factory settings for
    the PIV application on your YubiKey.
    """

    click.echo('Resetting PIV data...')
    ctx.obj['controller'].reset()
    click.echo(
        'Success! All PIV data have been cleared from your YubiKey.')
    click.echo('Your YubiKey now has the default PIN, PUK and Management Key:')
    click.echo('\tPIN:\t123456')
    click.echo('\tPUK:\t12345678')
    click.echo(
        '\tManagement Key:\t010203040506070801020304050607080102030405060708')


@piv.command('generate-key')
@click.pass_context
@click_slot_argument
@click_management_key_option
@click_pin_option
@click.option(
    '-a', '--algorithm', help='Algorithm to use in key generation.',
    type=UpperCaseChoice(
        ['RSA1024', 'RSA2048', 'ECCP256', 'ECCP384']), default='RSA2048',
    show_default=True)
@click_format_option
@click_pin_policy_option
@click_touch_policy_option
@click.argument(
    'public-key-output', type=click.File('wb'), metavar='PUBLIC-KEY')
def generate_key(
    ctx, slot, public_key_output, management_key, pin, algorithm,
        format, pin_policy, touch_policy):
    """
    Generate an asymmetric key pair.

    The private key is generated on the YubiKey, and written to one of the
    slots.

    \b
    SLOT        PIV slot where private key should be stored.
    PUBLIC-KEY  File containing the generated public key. Use '-' to use stdout.
    """

    controller = ctx.obj['controller']

    _ensure_authenticated(ctx, controller, pin, management_key)

    algorithm = ALGO.from_string(algorithm)

    if pin_policy:
        pin_policy = PIN_POLICY.from_string(pin_policy)
    if touch_policy:
        touch_policy = TOUCH_POLICY.from_string(touch_policy)

    _check_algorithm(ctx, controller, algorithm)
    _check_pin_policy(ctx, controller, pin_policy)
    _check_touch_policy(ctx, controller, touch_policy)

    public_key = controller.generate_key(
        slot,
        algorithm,
        pin_policy,
        touch_policy)

    key_encoding = format
    public_key_output.write(public_key.public_bytes(
            encoding=key_encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))


@piv.command('import-certificate')
@click.pass_context
@click_slot_argument
@click_management_key_option
@click_pin_option
@click.option(
    '-p', '--password', help='A password may be needed to decrypt the data.')
@click.argument('cert', type=click.File('rb'), metavar='CERTIFICATE')
def import_certificate(
        ctx, slot, management_key, pin, cert, password):
    """
    Import a X.509 certificate.

    Write a certificate to one of the slots on the YubiKey.

    \b
    SLOT            PIV slot to import the certificate to.
    CERTIFICATE     File containing the certificate. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']
    _ensure_authenticated(ctx, controller, pin, management_key)

    data = cert.read()

    while True:
        if password is not None:
            password = password.encode()
        try:
            cert = parse_certificate(data, password)
        except (ValueError, TypeError):
            if password is None:
                password = click.prompt(
                    'Enter password to decrypt certificate',
                    default='', hide_input=True,
                    show_default=False)
                continue
            else:
                password = None
                click.echo('Wrong password.')
            continue
        break

    controller.import_certificate(slot, cert)


@piv.command('import-key')
@click.pass_context
@click_slot_argument
@click_pin_option
@click_management_key_option
@click_pin_policy_option
@click_touch_policy_option
@click.argument('private-key', type=click.File('rb'), metavar='PRIVATE-KEY')
@click.option(
    '-p', '--password', help='Password used to decrypt the private key.')
def import_key(
        ctx, slot, management_key, pin, private_key,
        pin_policy, touch_policy, password):
    """
    Import a private key.

    Write a private key to one of the slots on the YubiKey.

    \b
    SLOT        PIV slot to import the private key to.
    PRIVATE-KEY File containing the private key. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']
    _ensure_authenticated(ctx, controller, pin, management_key)

    data = private_key.read()

    while True:
        if password is not None:
            password = password.encode()
        try:
            private_key = parse_private_key(data, password)
        except (ValueError, TypeError):
            if password is None:
                password = click.prompt(
                    'Enter password to decrypt key',
                    default='', hide_input=True,
                    show_default=False)
                continue
            else:
                password = None
                click.echo('Wrong password.')
            continue
        break

    if pin_policy:
        pin_policy = PIN_POLICY.from_string(pin_policy)
    if touch_policy:
        touch_policy = TOUCH_POLICY.from_string(touch_policy)

    _check_pin_policy(ctx, controller, pin_policy)
    _check_touch_policy(ctx, controller, touch_policy)
    _check_key_size(ctx, private_key)

    controller.import_key(
            slot,
            private_key,
            pin_policy,
            touch_policy)


@piv.command()
@click.pass_context
@click_slot_argument
@click_format_option
@click.argument('certificate', type=click.File('wb'), metavar='CERTIFICATE')
def attest(ctx, slot, certificate, format):
    """
    Generate a attestation certificate for a key.

    Attestation is used to show that an asymmetric key was generated on the
    YubiKey and therefore doesn't exist outside the device.

    \b
    SLOT        PIV slot with a private key to attest.
    CERTIFICATE File to write attestation certificate to. Use '-' to use stdout.
    """
    controller = ctx.obj['controller']
    try:
        cert = controller.attest(slot)
    except APDUError as e:
        logger.error('Attestation failed', exc_info=e)
        ctx.fail('Attestation failed.')
    certificate.write(cert.public_bytes(encoding=format))


@piv.command('export-certificate')
@click.pass_context
@click_slot_argument
@click_format_option
@click.argument('certificate', type=click.File('wb'), metavar='CERTIFICATE')
def export_certificate(ctx, slot, format, certificate):
    """
    Export a X.509 certificate.

    Reads a certificate from one of the slots on the YubiKey.

    \b
    SLOT        PIV slot to read certificate from.
    CERTIFICATE File to write certificate to. Use '-' to use stdout.
    """
    controller = ctx.obj['controller']
    try:
        cert = controller.read_certificate(slot)
    except APDUError as e:
        if e.sw == SW.NOT_FOUND:
            ctx.fail('No certificate found.')
        else:
            logger.error('Failed to read certificate from slot %s', slot,
                         exc_info=e)
    certificate.write(cert.public_bytes(encoding=format))


@piv.command('set-chuid')
@click.pass_context
@click_pin_option
@click_management_key_option
def set_chuid(ctx, management_key, pin):
    """
    Generate and set a CHUID on the YubiKey.
    """
    controller = ctx.obj['controller']
    _ensure_authenticated(ctx, controller, pin, management_key)
    controller.update_chuid()


@piv.command('set-ccc')
@click.pass_context
@click_pin_option
@click_management_key_option
def set_ccc(ctx, management_key, pin):
    """
    Generate and set a CCC on the YubiKey.
    """
    controller = ctx.obj['controller']
    _ensure_authenticated(ctx, controller, pin, management_key)
    controller.update_ccc()


@piv.command('set-pin-retries')
@click.pass_context
@click.argument(
    'pin-retries', type=click.IntRange(1, 255), metavar='PIN-RETRIES')
@click.argument(
    'puk-retries', type=click.IntRange(1, 255), metavar='PUK-RETRIES')
@click_management_key_option
@click_pin_option
@click_force_option
def set_pin_retries(ctx, management_key, pin, pin_retries, puk_retries, force):
    """
    Set the number of PIN and PUK retries.
    NOTE: This will reset the PIN and PUK to their factory defaults.
    """
    controller = ctx.obj['controller']
    _ensure_authenticated(
        ctx, controller, pin, management_key, require_pin_and_key=True,
        no_prompt=force)
    click.echo('WARNING: This will reset the PIN and PUK to the factory '
               'defaults!')
    force or click.confirm('Set PIN and PUK retry counters to: {} {}?'.format(
        pin_retries, puk_retries), abort=True)
    try:
        controller.set_pin_retries(pin_retries, puk_retries)
        click.echo('Default PINs are set.')
        click.echo('PIN:    123456')
        click.echo('PUK:    12345678')
    except Exception as e:
        logger.error('Failed to set PIN retries', exc_info=e)
        ctx.fail('Setting pin retries failed.')


@piv.command('generate-certificate')
@click.pass_context
@click_slot_argument
@click_management_key_option
@click_pin_option
@click.argument('public-key', type=click.File('rb'), metavar='PUBLIC-KEY')
@click.option(
    '-s', '--subject',
    help='A subject name for the certificate.', required=True)
@click.option(
    '-d', '--valid-days',
    help='Number of days until the certificate expires.',
    type=click.INT, default=365, show_default=True)
def generate_certificate(
        ctx, slot, management_key, pin, public_key, subject, valid_days):
    """
    Generate a self-signed X.509 certificate.

    A self-signed certificate is generated and written to one of the slots on
    the YubiKey. A private key need to exist in the slot.

    \b
    SLOT            PIV slot where private key is stored.
    PUBLIC-KEY      File containing a public key. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']
    _ensure_authenticated(
        ctx, controller, pin, management_key, require_pin_and_key=True)

    data = public_key.read()
    public_key = serialization.load_pem_public_key(
        data, default_backend())

    now = datetime.datetime.now()
    valid_to = now + datetime.timedelta(days=valid_days)

    try:
        controller.generate_self_signed_certificate(
            slot, public_key, subject, now, valid_to,
            touch_callback=prompt_for_touch)

    except APDUError as e:
        logger.error('Failed to generate certificate for slot %s', slot,
                     exc_info=e)
        ctx.fail('Certificate generation failed.')

    except InvalidSignature:
        ctx.fail('Invalid signature, certificate not imported.')


@piv.command('generate-csr')
@click.pass_context
@click_slot_argument
@click_pin_option
@click.argument('public-key', type=click.File('rb'), metavar='PUBLIC-KEY')
@click.argument('csr-output', type=click.File('wb'), metavar='CSR')
@click.option(
    '-s', '--subject',
    help='A subject name for the requested certificate.', required=True)
def generate_certificate_signing_request(
        ctx, slot, pin, public_key, csr_output, subject):
    """
    Generate a Certificate Signing Request (CSR).

    A private key need to exist in the slot.

    \b
    SLOT        PIV slot where the private key is stored.
    PUBLIC-KEY  File containing a public key. Use '-' to use stdin.
    CSR         File to write CSR to. Use '-' to use stdout.
    """
    controller = ctx.obj['controller']
    _verify_pin(ctx, controller, pin)

    data = public_key.read()
    public_key = serialization.load_pem_public_key(
        data, default_backend())

    try:
        csr = controller.generate_certificate_signing_request(
            slot, public_key, subject, touch_callback=prompt_for_touch)
    except APDUError:
        ctx.fail('Certificate Signing Request generation failed.')

    csr_output.write(csr.public_bytes(encoding=serialization.Encoding.PEM))


@piv.command('delete-certificate')
@click.pass_context
@click_slot_argument
@click_management_key_option
@click_pin_option
def delete_certificate(ctx, slot, management_key, pin):
    """
    Delete a certificate.

    Delete a certificate from a slot on the YubiKey.
    """
    controller = ctx.obj['controller']
    _ensure_authenticated(ctx, controller, pin, management_key)
    controller.delete_certificate(slot)


@piv.command('change-pin')
@click.pass_context
@click.option(
    '-P', '--pin', help='Current PIN code.')
@click.option('-n', '--new-pin', help='A new PIN.')
def change_pin(ctx, pin, new_pin):
    """
    Change the PIN code.

    The PIN can be up to 8 characters long, and supports any type of
    alphanumeric characters. For cross-platform compatibility,
    a PIN of 6 - 8 numeric digits is recommended.
    """
    controller = ctx.obj['controller']
    if not pin:
        pin = _prompt_pin(ctx, prompt='Enter your current PIN')
    if not new_pin:
        new_pin = click.prompt(
            'Enter your new PIN', default='', hide_input=True,
            show_default=False, confirmation_prompt=True)
    try:
        controller.change_pin(pin, new_pin)
    except APDUError as e:
        logger.error('Failed to change PIN', exc_info=e)
        ctx.fail('Changing the PIN failed.')
    click.echo('New PIN set.')


@piv.command('change-puk')
@click.pass_context
@click.option('-p', '--puk', help='Current PUK code.')
@click.option('-n', '--new-puk', help='A new PUK code.')
def change_puk(ctx, puk, new_puk):
    """
    Change the PUK code.

    If the PIN is lost or blocked it can be reset using a PUK.
    """
    controller = ctx.obj['controller']
    if not puk:
        puk = _prompt_pin(ctx, prompt='Enter your current PUK')
    if not new_puk:
        new_puk = click.prompt(
            'Enter your new PUK', default='', hide_input=True,
            show_default=False, confirmation_prompt=True)

    (success, retries) = controller.change_puk(puk, new_puk)

    if success:
        click.echo('New PUK set.')
    else:
        logger.debug('Failed to change PUK, %d tries left', retries)
        ctx.fail('PUK change failed - %d tries left.' % retries)


@piv.command('change-management-key')
@click.pass_context
@click_pin_option
@click.option(
    '-t', '--touch', is_flag=True,
    help='Require touch on YubiKey when prompted for management key.')
@click.option(
    '-n', '--new-management-key', help='A new management key.',
    callback=click_parse_management_key)
@click.option(
    '-m', '--management-key', help='Current management key.',
    callback=click_parse_management_key)
@click.option(
    '-p', '--protect', is_flag=True,
    help='Store new management key on your YubiKey, protected by PIN.'
         ' A random key will be used if no key is provided.')
@click.option(
    '-g', '--generate', is_flag=True, help='Generate a random management key. '
    'Implied by --protect unless --new-management-key is also given. '
    'Conflicts with --new-management-key.')
@click_force_option
def change_management_key(
        ctx, management_key, pin, new_management_key, touch, protect, generate,
        force):
    """
    Change the management key.

    Management functionality is guarded by a 24 byte management key.
    This key is required for administrative tasks, such as generating key pairs.
    A random key may be generated and stored on the YubiKey, protected by PIN.
    """
    controller = ctx.obj['controller']

    _ensure_authenticated(
        ctx, controller, pin, management_key,
        require_pin_and_key=protect,
        mgm_key_prompt='Enter your current management key '
                       '[blank to use default key]',
        no_prompt=force)

    if new_management_key and generate:
        ctx.fail('Invalid options: --new-management-key conflicts with '
                 '--generate')

    # Touch not supported on NEO.
    if touch and controller.version < (4, 0, 0):
        ctx.fail('Require touch not supported on this YubiKey.')

    # If an old stored key needs to be cleared, the PIN is needed.
    if not protect and controller.has_stored_key:
        if pin:
            _verify_pin(ctx, controller, pin, no_prompt=force)
        else:
            force or click.confirm(
                    'The current management key is stored on the YubiKey'
                    ' and will not be cleared if no PIN is provided. Continue?',
                    abort=True)

    if not new_management_key and not protect:
        if generate:
            new_management_key = generate_random_management_key()

            if not protect:
                click.echo(
                    'Generated management key: {}'.format(
                        b2a_hex(new_management_key).decode('utf-8')))

        elif force:
            ctx.fail('New management key not given. Please remove the --force '
                     'flag, or set the --generate flag or the '
                     '--new-management-key option.')

        else:
            new_management_key = click.prompt(
                'Enter your new management key',
                hide_input=True, confirmation_prompt=True)

    if new_management_key and type(new_management_key) is not bytes:
        try:
            new_management_key = a2b_hex(new_management_key)
        except Exception:
            ctx.fail('New management key has the wrong format.')

    try:
        controller.set_mgm_key(
            new_management_key, touch=touch, store_on_device=protect)
    except APDUError as e:
        logger.error('Failed to change management key', exc_info=e)
        ctx.fail('Changing the management key failed.')


@piv.command('unblock-pin')
@click.pass_context
@click.option('-p', '--puk', required=False)
@click.option('-n', '--new-pin', required=False, metavar='NEW-PIN')
def unblock_pin(ctx, puk, new_pin):
    """
    Unblock the PIN.

    Reset the PIN using the PUK code.
    """
    controller = ctx.obj['controller']
    if not puk:
        puk = click.prompt(
            'Enter PUK', default='', show_default=False, hide_input=True)
    if not new_pin:
        new_pin = click.prompt(
            'Enter a new PIN', default='', show_default=False, hide_input=True)
    controller.unblock_pin(puk, new_pin)


def _prompt_management_key(
        ctx, prompt='Enter a management key [blank to use default key]'):
    management_key = click.prompt(
        prompt, default='', hide_input=True, show_default=False)
    if management_key == '':
        return DEFAULT_MANAGEMENT_KEY
    try:
        return a2b_hex(management_key)
    except Exception:
        ctx.fail('Management key has the wrong format.')


def _prompt_pin(ctx, prompt='Enter PIN'):
    return click.prompt(
        prompt, default='', hide_input=True, show_default=False)


def _ensure_authenticated(
        ctx, controller, pin=None, management_key=None,
        require_pin_and_key=False,
        mgm_key_prompt=None,
        no_prompt=False):

    if controller.has_protected_key:
        if not management_key:
            _verify_pin(ctx, controller, pin, no_prompt=no_prompt)
        else:
            _authenticate(ctx, controller, management_key, mgm_key_prompt,
                          no_prompt=no_prompt)
    else:
        if require_pin_and_key:
            _verify_pin(ctx, controller, pin, no_prompt=no_prompt)
        _authenticate(ctx, controller, management_key, mgm_key_prompt,
                      no_prompt=no_prompt)


def _verify_pin(ctx, controller, pin, no_prompt=False):
    if not pin:
        if no_prompt:
            ctx.fail('PIN required.')
        else:
            pin = _prompt_pin(ctx)

    try:
        controller.verify(pin, touch_callback=prompt_for_touch)
    except APDUError:
        ctx.fail('PIN verification failed.')


def _authenticate(ctx, controller, management_key, mgm_key_prompt,
                  no_prompt=False):
    if not management_key:
        if no_prompt:
            ctx.fail('Management key required.')
        else:
            if mgm_key_prompt is None:
                management_key = _prompt_management_key(ctx)
            else:
                management_key = _prompt_management_key(ctx, mgm_key_prompt)
    try:
        controller.authenticate(management_key, touch_callback=prompt_for_touch)
    except (APDUError, TypeError):
        ctx.fail('Authentication with management key failed.')


def _check_algorithm(ctx, controller, algorithm):
    #  ECCP384 not supported on NEO.
    if algorithm == ALGO.ECCP384 and controller.version < (4, 0, 0):
        ctx.fail('ECCP384 is not supported by this YubiKey.')
    if algorithm == ALGO.RSA1024 and ctx.obj['dev'].is_fips:
        ctx.fail('RSA1024 is not supported by this YubiKey.')


def _check_key_size(ctx, private_key):
    if ctx.obj['dev'].is_fips and private_key.key_size == 1024:
        ctx.fail('1024 is not a supported key size on this YubiKey.')


def _check_pin_policy(ctx, controller, pin_policy):
    if pin_policy is not None and not controller.supports_pin_policies:
        ctx.fail('PIN policy is not supported by this YubiKey.')
    if ctx.obj['dev'].is_fips and pin_policy == PIN_POLICY.NEVER:
        ctx.fail('PIN policy NEVER is not supported by this YubiKey.')


def _check_touch_policy(ctx, controller, touch_policy):
    if touch_policy is not None:
        if len(controller.supported_touch_policies) == 0:
            ctx.fail('Touch policy is not supported by this YubiKey.')
        elif touch_policy not in controller.supported_touch_policies:
            ctx.fail('Touch policy {} not supported by this YubiKey.'.format(
                touch_policy.name))


piv.transports = TRANSPORT.CCID
