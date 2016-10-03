import sys
import unittest
import time
import click
import traceback
try:
    from ykman.util import TRANSPORT
    from ykman.descriptor import get_descriptors
    from click.testing import CliRunner
    from ykman.cli.__main__ import cli
    click.confirm(
        "Run integration tests? This will erase data on the YubiKey,"
        " make sure it is a key used for development.", abort=True)
except Exception:
    sys.exit()


def ykman_cli(*argv):
    runner = CliRunner()
    result = runner.invoke(cli, list(argv), obj={})
    if result.exit_code != 0:
        click.echo(result.output)
        traceback.print_tb(result.exc_info[2])
        raise result.exception
    return result.output


def _one_yubikey():
    return len(list(get_descriptors())) == 1


def _has_mode(mode):
    yubikeys = list(get_descriptors())
    if len(yubikeys) is not 1:
        return False
    return yubikeys[0].mode.has_transport(mode)


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
class TestYkmanInfo(unittest.TestCase):

    def test_ykman_info(self):
        time.sleep(3)
        info = ykman_cli('info')
        self.assertIn('Device name:', info)
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info)


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
@unittest.skipIf(not _has_mode(TRANSPORT.OTP), "OTP needs to be enabled")
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


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
@unittest.skipIf(not _has_mode(TRANSPORT.OTP), "OTP needs to be enabled")
class TestSlotProgramming(unittest.TestCase):

    def test_ykman_program_otp_slot_2(self):
        output = ykman_cli('slot', 'otp', '2', '-f')
        self.assertIn('Using serial as public ID:', output)
        self.assertIn('Using a randomly generated private ID:', output)
        self.assertIn('Using a randomly generated secret key:', output)
        self._check_slot_2_programmed()

    def test_ykman_program_chalresp_slot_2(self):
        output = ykman_cli('slot', 'chalresp', '2', '-f')
        self.assertIn('Using a randomly generated key.', output)
        self._check_slot_2_programmed()

    def test_ykman_program_hotp_slot_2(self):
        output = ykman_cli(
            'slot', 'hotp', '2',
            '27KIZZE3SD7GE2FVJJBAXEI3I6RRTPGM', '-f')
        self.assertIn('Programming HOTP credential in slot 2...', output)
        self._check_slot_2_programmed()

    def test_ykman_program_static_slot_2(self):
        output = ykman_cli(
            'slot', 'static', '2',
            'higngdukgerjktbbikrhirngtlkkttkb', '-f')
        self.assertIn('Setting static password in slot 2...', output)
        self._check_slot_2_programmed()

    def test_update_settings_enter_slot_2(self):
        ykman_cli('slot', 'otp', '2', '-f')
        output = ykman_cli('slot', 'settings', '2', '-f', '--no-enter')
        self.assertIn('Updating settings for slot', output)

    def test_delete_slot_2(self):
        ykman_cli('slot', 'otp', '2', '-f')
        output = ykman_cli('slot', 'delete', '2', '-f')
        self.assertIn('Deleting slot', output)
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: empty', status)

    def _check_slot_2_programmed(self):
        status = ykman_cli('slot', 'info')
        self.assertIn('Slot 2: programmed', status)


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
@unittest.skipIf(
    not _has_mode(TRANSPORT.CCID),
    "CCID needs to be enabled for this test.")
class TestOpenPGP(unittest.TestCase):

    def test_openpgp_info(self):
        output = ykman_cli('openpgp', 'info')
        self.assertIn('OpenPGP version:', output)

    def test_openpgp_reset(self):
        output = ykman_cli('openpgp', 'reset', '-f')
        self.assertIn(
            'Success! All data has been cleared and default PINs are set.',
            output)
