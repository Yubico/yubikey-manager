import os
import sys
import unittest
import time
import click
from ykman.util import TRANSPORT
from test.util import ykman_cli

URI_HOTP_EXAMPLE = 'otpauth://hotp/Example:demo@example.com?' \
        'secret=JBSWY3DPK5XXE3DEJ5TE6QKUJA======&issuer=Example&counter=1'

URI_TOTP_EXAMPLE = (
        'otpauth://totp/ACME%20Co:john.doe@email.com?'
        'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co'
        '&algorithm=SHA1&digits=6&period=30')

DEFAULT_MANAGEMENT_KEY = '010203040506070801020304050607080102030405060708'

_one_yubikey = False
if os.environ.get('INTEGRATION_TESTS') == 'TRUE':
    try:
        from ykman.descriptor import get_descriptors
        click.confirm(
            'Run integration tests? This will erase data on the YubiKey,'
            ' make sure it is a key used for development.', abort=True)
        _one_yubikey = len(list(get_descriptors())) == 1
    except Exception:
        sys.exit()
    _skip = False
else:
    _skip = True


def _has_mode(mode):
    if not _one_yubikey:
        return False
    yubikeys = list(get_descriptors())
    if len(yubikeys) is not 1:
        return False
    return yubikeys[0].mode.has_transport(mode)


def _get_version():
    if not _one_yubikey:
        return None
    return list(get_descriptors())[0].version


def _is_NEO():
    if _one_yubikey:
        return _get_version() < (4, 0, 0)
    else:
        return False


def _no_attestation():
    if _one_yubikey:
        return _get_version() < (4, 3, 0)
    else:
        return False


@unittest.skipIf(_skip, 'INTEGRATION_TESTS != TRUE')
@unittest.skipIf(not _one_yubikey, 'A single YubiKey need to be connected.')
class TestYkmanInfo(unittest.TestCase):

    def test_ykman_info(self):
        time.sleep(3)
        info = ykman_cli('info')
        self.assertIn('Device name:', info)
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info)


@unittest.skipIf(_skip, 'INTEGRATION_TESTS != TRUE')
@unittest.skipIf(not _one_yubikey, 'A single YubiKey need to be connected.')
@unittest.skipIf(not _has_mode(TRANSPORT.OTP), 'OTP needs to be enabled')
class TestSlotStatus(unittest.TestCase):

    def test_ykman_slot_info(self):
        info = ykman_cli('slot', 'info')
        self.assertIn('Slot 1:', info)
        self.assertIn('Slot 2:', info)

    def test_ykman_swap_slots(self):
        output = ykman_cli('slot', 'swap', '-f')
        self.assertIn('Swapping slots...', output)
        output = ykman_cli('slot', 'swap', '-f')
        self.assertIn('Swapping slots...', output)


@unittest.skipIf(_skip, 'INTEGRATION_TESTS != TRUE')
@unittest.skipIf(not _one_yubikey, 'A single YubiKey need to be connected.')
@unittest.skipIf(not _has_mode(TRANSPORT.OTP), 'OTP needs to be enabled')
class TestSlotProgramming(unittest.TestCase):

    def test_ykman_program_otp_slot_2(self):
        output = ykman_cli('slot', 'otp', '2', '-f')
        self.assertIn('Using device serial as public ID:', output)
        self.assertIn('Using a randomly generated private ID:', output)
        self.assertIn('Using a randomly generated secret key:', output)
        self._check_slot_2_programmed()

    def test_ykman_program_chalresp_slot_2(self):
        output = ykman_cli('slot', 'chalresp', '2', '-f')
        self.assertIn('Using a randomly generated key', output)
        self._check_slot_2_programmed()

    def test_chal_resp_totp(self):
        ykman_cli('slot', 'chalresp', '2', '-T', 'abba', '-f')
        self._check_slot_2_programmed()

    def test_ykman_program_hotp_slot_2(self):
        ykman_cli(
            'slot', 'hotp', '2',
            '27KIZZE3SD7GE2FVJJBAXEI3I6RRTPGM', '-f')
        self._check_slot_2_programmed()

    def test_ykman_program_static_slot_2(self):
        ykman_cli(
            'slot', 'static', '2',
            'higngdukgerjktbbikrhirngtlkkttkb', '-f')
        self._check_slot_2_programmed()

    def test_update_settings_enter_slot_2(self):
        ykman_cli('slot', 'otp', '2', '-f')
        output = ykman_cli('slot', 'settings', '2', '-f', '--no-enter')
        self.assertIn('Updating settings for slot', output)

    def test_delete_slot_2(self):
        ykman_cli('slot', 'otp', '2', '-f')
        output = ykman_cli('slot', 'delete', '2', '-f')
        self.assertIn('Deleting the configuration', output)
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: empty', status)

    def _check_slot_2_programmed(self):
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: programmed', status)


@unittest.skipIf(_skip, 'INTEGRATION_TESTS != TRUE')
@unittest.skipIf(not _one_yubikey, 'A single YubiKey need to be connected.')
@unittest.skipIf(not _has_mode(TRANSPORT.OTP), 'OTP needs to be enabled')
class TestSlotCalculate(unittest.TestCase):

    def test_calculate_hex(self):
        ykman_cli('slot', 'delete', '2', '-f')
        ykman_cli('slot', 'chalresp', '2', 'abba', '-f')
        output = ykman_cli('slot', 'calculate', '2', 'abba')
        self.assertIn('f8de2586056d89d8b961a072d1245a495d2155e1', output)

    def test_calculate_totp(self):
        ykman_cli('slot', 'delete', '2', '-f')
        ykman_cli('slot', 'chalresp', '2', 'abba', '-f')
        output = ykman_cli('slot', 'calculate', '2', '999', '-T')
        self.assertEqual('533486', output.strip())
        output = ykman_cli('slot', 'calculate', '2', '999', '-T', '-d', '8')
        self.assertEqual('04533486', output.strip())
        output = ykman_cli('slot', 'calculate', '2', '-T')
        self.assertEqual(6, len(output.strip()))
        output = ykman_cli('slot', 'calculate', '2', '-T', '-d', '8')
        self.assertEqual(8, len(output.strip()))


@unittest.skipIf(_skip, 'INTEGRATION_TESTS != TRUE')
@unittest.skipIf(not _one_yubikey, 'A single YubiKey need to be connected.')
@unittest.skipIf(
    not _has_mode(TRANSPORT.CCID),
    'CCID needs to be enabled for this test.')
class TestOpenPGP(unittest.TestCase):

    def test_openpgp_info(self):
        output = ykman_cli('openpgp', 'info')
        self.assertIn('OpenPGP version:', output)

    def test_openpgp_reset(self):
        output = ykman_cli('openpgp', 'reset', '-f')
        self.assertIn(
            'Success! All data has been cleared and default PINs are set.',
            output)


@unittest.skipIf(_skip, 'INTEGRATION_TESTS != TRUE')
@unittest.skipIf(not _one_yubikey, 'A single YubiKey need to be connected.')
@unittest.skipIf(
    not _has_mode(TRANSPORT.CCID),
    'CCID needs to be enabled for this test.')
class TestOATH(unittest.TestCase):

    def test_oath_info(self):
        output = ykman_cli('oath', 'info')
        self.assertIn('OATH version:', output)

    def test_oath_add_credential(self):
        ykman_cli('oath', 'add', 'test-name', 'abba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name', creds)

    def test_oath_add_credential_with_space(self):
        ykman_cli('oath', 'add', 'test-name-space', 'ab ba')
        creds = ykman_cli('oath', 'list')
        self.assertIn('test-name-space', creds)

    def test_oath_hidden_cred(self):
        ykman_cli('oath', 'add', '_hidden:name', 'abba')
        creds = ykman_cli('oath', 'code')
        self.assertNotIn('_hidden:name', creds)
        creds = ykman_cli('oath', 'code', '-H')
        self.assertIn('_hidden:name', creds)

    def test_oath_add_uri_hotp(self):
        ykman_cli('oath', 'uri', URI_HOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        self.assertIn('Example:demo', creds)

    def test_oath_add_uri_totp(self):
        ykman_cli('oath', 'uri', URI_TOTP_EXAMPLE)
        creds = ykman_cli('oath', 'list')
        self.assertIn('john.doe', creds)

    def test_oath_code(self):
        ykman_cli('oath', 'add', 'test-name2', 'abba')
        creds = ykman_cli('oath', 'code')
        self.assertIn('test-name2', creds)

    def test_oath_reset(self):
        output = ykman_cli('oath', 'reset', '-f')
        self.assertIn(
            'Success! All credentials have been cleared from the device.',
            output)

    def test_oath_hotp_code(self):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'hotp-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'hotp-cred')
        self.assertIn('659165', cred)

    def test_oath_hotp_steam_code(self):
        ykman_cli('oath', 'add', '-o', 'HOTP', 'Steam:steam-cred', 'abba')
        cred = ykman_cli('oath', 'code', 'steam-cred')
        self.assertIn('CGC3K', cred)

    def test_oath_remove(self):
        ykman_cli('oath', 'add', 'remove-me', 'abba')
        ykman_cli('oath', 'remove', 'remove-me')
        self.assertNotIn('remove-me', ykman_cli('oath', 'list'))


@unittest.skipIf(_skip, 'INTEGRATION_TESTS != TRUE')
@unittest.skipIf(not _one_yubikey, 'A single YubiKey need to be connected.')
@unittest.skipIf(
    not _has_mode(TRANSPORT.CCID),
    'CCID needs to be enabled for this test.')
class TestPIV(unittest.TestCase):

    def test_piv_info(self):
        output = ykman_cli('piv', 'info')
        self.assertIn('PIV version:', output)

    def test_piv_reset(self):
        output = ykman_cli('piv', 'reset', '-f')
        self.assertIn('Success!', output)

    def test_piv_generate_key_default(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-m', DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    def test_piv_generate_key_rsa1024(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'RSA1024', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    def test_piv_generate_key_eccp256(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP256', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(_is_NEO(), 'ECCP384 not available.')
    def test_piv_generate_key_eccp384(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '-a', 'ECCP384', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(_is_NEO(), 'Pin policy not available.')
    def test_piv_generate_key_pin_policy_always(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--pin-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(_is_NEO(), 'Touch policy not available.')
    def test_piv_generate_key_touch_policy_always(self):
        output = ykman_cli(
            'piv', 'generate-key', '9a', '--touch-policy', 'ALWAYS', '-m',
            DEFAULT_MANAGEMENT_KEY, '-')
        self.assertIn('BEGIN PUBLIC KEY', output)

    @unittest.skipIf(_no_attestation(), 'Attestation not available.')
    def test_piv_attest_key(self):
        ykman_cli(
            'piv', 'generate-key', '9a', '-m', DEFAULT_MANAGEMENT_KEY, '-')
        output = ykman_cli('piv', 'attest', '9a', '-')
        self.assertIn('BEGIN CERTIFICATE', output)

    def test_piv_generate_self_signed(self):
        ykman_cli(
            'piv', 'generate-key', '9a', '-m',
            DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
        ykman_cli(
            'piv', 'generate-certificate', '9a', '/tmp/test-pub-key.pem',
            '-s', 'test-subject', '-P', '123456')
        output = ykman_cli('piv', 'info')
        self.assertIn('test-subject', output)

    def test_piv_generate_csr(self):
        ykman_cli(
            'piv', 'generate-key', '9a', '-m',
            DEFAULT_MANAGEMENT_KEY, '/tmp/test-pub-key.pem')
        output = ykman_cli(
            'piv', 'generate-csr', '9a', '/tmp/test-pub-key.pem',
            '-s', 'test-subject', '-P', '123456', '-')
        self.assertIn('BEGIN CERTIFICATE REQUEST', output)

    @unittest.skipIf(_no_attestation(), 'Attestation not available.')
    def test_piv_export_attestation_certificate(self):
        output = ykman_cli('piv', 'export-certificate', 'f9', '-')
        self.assertIn('BEGIN CERTIFICATE', output)

    def test_piv_change_management_key_derive(self):
        ykman_cli(
            'piv', 'change-management-key', '-d', '-P', '123456',
            '-m', DEFAULT_MANAGEMENT_KEY)
        output = ykman_cli('piv', 'info')
        self.assertIn('Management key is derived from PIN', output)
        ykman_cli('piv', 'reset', '-f')  # Cleanup, should maybe be done always?

    def test_piv_change_pin(self):
        ykman_cli('piv', 'change-pin', '-P', '123456', '-n', '654321')
        ykman_cli('piv', 'change-pin', '-P', '654321', '-n', '123456')

    def test_piv_change_puk(self):
        ykman_cli('piv', 'change-puk', '-p', '12345678', '-n', '87654321')
        ykman_cli('piv', 'change-puk', '-p', '87654321', '-n', '12345678')
