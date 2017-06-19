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
    DEFAULT_MANAGEMENT_KEY)
from ..driver_ccid import APDUError, SW_APPLICATION_NOT_FOUND
from .util import click_skip_on_help, click_callback, prompt_for_touch
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import utils
from binascii import b2a_hex, a2b_hex
import click
import os
import datetime


@click_callback()
def click_parse_piv_slot(ctx, param, val):
    try:
        return SLOT(int(val, 16))
    except:
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
        return a2b_hex(val)
    except:
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
    type=click.Choice(['PEM', 'DER']), default='PEM', show_default=True,
    help='Encoding format.', callback=click_parse_format)
click_pin_policy_option = click.option(
    '--pin-policy', type=click.Choice(['DEFAULT', 'NEVER', 'ONCE', 'ALWAYS']),
    help='PIN policy for slot.')
click_touch_policy_option = click.option(
    '--touch-policy', type=click.Choice(
        ['DEFAULT', 'NEVER', 'ALWAYS', 'CACHED']),
    help='Touch policy for slot.')


@click.group()
@click.pass_context
@click_skip_on_help
def piv(ctx):
    """
    Manage YubiKey PIV functionality.
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

    # Largest possible number of PIN tries to get back is 15
    tries = controller.get_pin_tries()
    tries = '15 or more.' if tries == 15 else tries
    click.echo('PIN tries remaining: %s' % tries)
    if controller.puk_blocked:
        click.echo('PUK blocked.')
    if controller.has_derived_key:
        click.echo('Management key is derived from PIN.')
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

    This action will wipe all data and reset factory settings for
    the PIV functionality on the device.
    """

    click.echo('Resetting PIV data...')
    ctx.obj['controller'].reset()
    click.echo(
        'Success! All PIV data have been cleared from the device.')
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
    type=click.Choice(
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

    The private key is generated on the device, and written to one of the slots.

    \b
    SLOT        PIV slot where private key should be stored.
    PUBLIC-KEY  File containing the generated public key. Use '-' to use stdout.
    """
    controller = ctx.obj['controller']
    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)

    algorithm = ALGO.from_string(algorithm)

    if pin_policy:
        pin_policy = PIN_POLICY.from_string(pin_policy)
    if touch_policy:
        touch_policy = TOUCH_POLICY.from_string(touch_policy)

    _check_eccp384(ctx, controller, algorithm)
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

    Write a certificate in one of the slots on the device.

    \b
    SLOT            PIV slot to import the certificate to.
    CERTIFICATE     File containing the certificate. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']
    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)

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

    Write a private key in one of the slots on the device.

    \b
    SLOT        PIV slot to import the private key to.
    PRIVATE-KEY File containing the private key. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']
    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)

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

    Attestation is used to show that a certain asymmetric key has been
    generated on device and not imported.

    \b
    SLOT        PIV slot with a private key to attest.
    CERTIFICATE File to write attestation certificate to. Use '-' to use stdout.
    """
    controller = ctx.obj['controller']
    try:
        cert = controller.attest(slot)
    except APDUError:
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

    Reads a certificate from one of the slots on the device.

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
    certificate.write(cert.public_bytes(encoding=format))


@piv.command('set-chuid')
@click.pass_context
@click_pin_option
@click_management_key_option
def set_chuid(ctx, management_key, pin):
    """
    Generate and set a CHUID on the device.
    """
    controller = ctx.obj['controller']
    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)
    controller.update_chuid()


@piv.command('set-ccc')
@click.pass_context
@click_pin_option
@click_management_key_option
def set_ccc(ctx, management_key, pin):
    """
    Generate and set a CCC on the device.
    """
    controller = ctx.obj['controller']
    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)
    controller.update_ccc()


@piv.command('set-pin-retries')
@click.pass_context
@click.argument(
    'pin-retries', type=click.IntRange(1, 255), metavar='PIN-RETRIES')
@click.argument(
    'puk-retries', type=click.IntRange(1, 255), metavar='PUK-RETRIES')
@click_management_key_option
@click_pin_option
def set_pin_retries(ctx, management_key, pin, pin_retries, puk_retries):
    """
    Set the number of PIN and PUK retries.
    """
    controller = ctx.obj['controller']
    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    try:
        controller.set_pin_retries(pin_retries, puk_retries)
    except:
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
    the device. A private key need to exist in the slot.

    \b
    SLOT            PIV slot where private key is stored.
    PUBLIC-KEY      File containing a public key. Use '-' to use stdin.
    """
    controller = ctx.obj['controller']

    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)
        if not pin:
            pin = _prompt_pin(ctx)
        _verify_pin(ctx, controller, pin)

    data = public_key.read()
    public_key = serialization.load_pem_public_key(
        data, default_backend())

    algorithm = ALGO.from_public_key(public_key)

    builder = x509.CertificateBuilder()
    builder = builder.public_key(public_key)
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject), ]))

    # Same as subject on self-signed certificates.
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject), ]))

    # x509.random_serial_number added in cryptography 1.6
    serial = utils.int_from_bytes(os.urandom(20), 'big') >> 1
    builder = builder.serial_number(serial)

    now = datetime.datetime.now()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=valid_days))

    try:
        cert = controller.sign_cert_builder(
            slot, algorithm, builder, touch_callback=prompt_for_touch)
    except APDUError:
        ctx.fail('Certificate generation failed.')

    # Verify that the public key used in the certificate
    # is from the same keypair as the private key.
    cert_signature = cert.signature
    cert_bytes = cert.tbs_certificate_bytes
    if isinstance(public_key, rsa.RSAPublicKey):
        verifier = public_key.verifier(
            cert_signature, padding.PKCS1v15(), cert.signature_hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        verifier = public_key.verifier(
            cert_signature, ec.ECDSA(cert.signature_hash_algorithm))
    verifier.update(cert_bytes)
    try:
        verifier.verify()
    except InvalidSignature:
        ctx.fail('Invalid signature, certificate not imported.')
    controller.import_certificate(slot, cert)


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
    if not pin:
        pin = _prompt_pin(ctx)
    _verify_pin(ctx, controller, pin)

    data = public_key.read()
    public_key = serialization.load_pem_public_key(
        data, default_backend())

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject), ]))

    try:
        csr = controller.sign_csr_builder(
            slot, public_key, builder, touch_callback=prompt_for_touch)
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

    Delete a certificate from a slot on the device.
    """
    controller = ctx.obj['controller']
    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(ctx)
        _authenticate(ctx, controller, management_key)
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
    except APDUError:
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
    try:
        controller.change_puk(puk, new_puk)
    except APDUError:
        ctx.fail('Changing the PUK failed.')
    click.echo('New PUK set.')


@piv.command('change-management-key')
@click.pass_context
@click_pin_option
@click.option(
    '-t', '--touch', is_flag=True,
    help='Require touch on YubiKey when prompted for management key.')
@click.option('-n', '--new-management-key', help='A new management key.')
@click.option(
    '-d', '--derive-from-pin', is_flag=True,
    help='Derive the management key from the current PIN code. \
            Blocks the PUK code.')
@click.option(
    '-m', '--management-key', help='Current management key.',
    callback=click_parse_management_key)
def change_management_key(
        ctx, management_key, pin, new_management_key, touch, derive_from_pin):
    """
    Change the management key.

    Management functionality is guarded by a 24 byte management key.
    This key is required for administrative tasks, such as generating key pairs.
    """
    controller = ctx.obj['controller']

    if controller.has_derived_key:
        if not pin:
            pin = _prompt_pin(pin)
        _verify_pin(ctx, controller, pin)
    else:
        if not management_key:
            management_key = _prompt_management_key(
                ctx, prompt='Enter your current management key'
                            ' [blank to use the default key]')
        _authenticate(ctx, controller, management_key)

    # Touch not supported on NEO.
    if touch and controller.version < (4, 0, 0):
        ctx.fail('Require touch not supported on your device.')

    if derive_from_pin:
        if not pin:
            pin = _prompt_pin(pin)
        controller.use_derived_key(pin, touch=touch)
    else:
        if not new_management_key:
            new_management_key = click.prompt(
                'Enter your new management key',
                default='', show_default=False,
                hide_input=True, confirmation_prompt=True)
        try:
            new_management_key = a2b_hex(new_management_key)
        except:
            ctx.fail('New management key has the wrong format.')
        try:
            controller.set_mgm_key(new_management_key, touch=touch)
        except APDUError:
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
    except:
        ctx.fail('Management key has the wrong format.')


def _prompt_pin(ctx, prompt='Enter PIN'):
    return click.prompt(
        prompt, default='', hide_input=True, show_default=False)


def _verify_pin(ctx, controller, pin):
    try:
        controller.verify(pin, touch_callback=prompt_for_touch)
    except APDUError:
        ctx.fail('PIN verification failed.')


def _authenticate(ctx, controller, management_key):
    try:
        controller.authenticate(management_key, touch_callback=prompt_for_touch)
    except APDUError:
        ctx.fail('Authentication with management key failed.')


def _check_eccp384(ctx, controller, algorithm):
    #  ECCP384 not supported on NEO.
    if algorithm == ALGO.ECCP384 and controller.version < (4, 0, 0):
        ctx.fail('ECCP384 is not supported by this device.')


def _check_pin_policy(ctx, controller, pin_policy):
    #  Pin policy not supported on NEO.
    if pin_policy is not None and controller.version < (4, 0, 0):
        ctx.fail('Pin policy is not supported by this device.')


def _check_touch_policy(ctx, controller, touch_policy):
    #  Touch policy not supported on NEO.
    if touch_policy is not None:
        if controller.version < (4, 0, 0):
            ctx.fail('Touch policy is not supported by this device.')
        if touch_policy == TOUCH_POLICY.CACHED \
                and controller.version < (4, 3, 0):
            #  Cached policy was added in 4.3
            ctx.fail('Touch policy "CACHED" not supported by this device.')


piv.transports = TRANSPORT.CCID
