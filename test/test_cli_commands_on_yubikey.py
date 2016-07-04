import unittest
import time
import sys
import click
from subprocess import check_output
from ykman.util import list_yubikeys, BitflagEnum, TRANSPORT

if not click.confirm("Run integration tests? This will erase data on the YubiKey, make sure it is a key used for development."):
    sys.exit()

def _one_yubikey():
    return len(list_yubikeys()) == 1

def _has_mode(mode):
    yubikeys = list_yubikeys()
    if len(yubikeys) is not 1:
        return False
    return BitflagEnum.has(list_yubikeys()[0], mode)


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
class TestYkmanInfo(unittest.TestCase):

    def test_ykman_info(self):
        time.sleep(3)
        info = check_output(['ykman', 'info']).decode('ascii')
        self.assertIn('Device name:', info) 
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info)


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
@unittest.skipIf(not _has_mode(TRANSPORT.OTP), "OTP needs to be enabled")
class TestSlotStatus(unittest.TestCase):

    def test_ykman_slot_info(self):
        info = check_output(['ykman', 'slot', 'info']).decode('ascii')
        self.assertIn('Slot 1:', info) 
        self.assertIn('Slot 2:', info)

    def test_ykman_swap_slots(self):
        output = check_output(['ykman', 'slot', 'swap', '-f']).decode('ascii')
        self.assertIn('Swapping slots...', output)
        output = check_output(['ykman', 'slot', 'swap', '-f']).decode('ascii')
        self.assertIn('Swapping slots...', output)


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
@unittest.skipIf(not _has_mode(TRANSPORT.OTP), "OTP needs to be enabled")
class TestSlotProgramming(unittest.TestCase):

    def tearDown(self):
        self._check_slot_2_programmed()
        self._delete_slot_2()

    def test_ykman_program_otp_slot_2(self):
        output = check_output(['ykman', 'slot', 'otp', '2', '-f']).decode('ascii')
        self.assertIn('Using serial as public ID:', output)
        self.assertIn('Using a randomly generated private ID:', output)
        self.assertIn('Using a randomly generated secret key:', output)

    def test_ykman_program_chalresp_slot_2(self):
        output = check_output(['ykman', 'slot', 'chalresp', '2', '-f']).decode('ascii')
        self.assertIn('Using a randomly generated key.', output)

    def test_ykman_program_hotp_slot_2(self):
        output = check_output(['ykman', 'slot', 'hotp', '2', '27KIZZE3SD7GE2FVJJBAXEI3I6RRTPGM', '-f']).decode('ascii')
        self.assertIn('Programming HOTP credential in slot 2...', output)

    def test_ykman_program_static_slot_2(self):
        self._delete_slot_2()
        output = check_output(['ykman', 'slot', 'static', '2', 'higngdukgerjktbbikrhirngtlkkttkb', '-f']).decode('ascii')
        self.assertIn('Setting static password in slot 2...', output)

    def _delete_slot_2(self):
        output = check_output(['ykman', 'slot', 'delete', '2', '-f']).decode('ascii')
        self.assertIn('Deleting slot: 2...', output)
        status = check_output(['ykman', 'slot', 'info']).decode('ascii')
        self.assertIn('Slot 2: empty', status)

    def _check_slot_2_programmed(self):
        status = check_output(['ykman', 'slot', 'info']).decode('ascii')
        self.assertIn('Slot 2: programmed', status)


@unittest.skipIf(not _one_yubikey(), "A single YubiKey need to be connected.")
@unittest.skipIf(not _has_mode(TRANSPORT.CCID), "CCID needs to be enabled for this test.")
class TestOpenPGP(unittest.TestCase):

    def test_openpgp_info(self):
        output = check_output(['ykman', 'openpgp', 'info']).decode('ascii')
        self.assertIn('OpenPGP version:', output)

    def test_openpgp_reset(self):
        output = check_output(['ykman', 'openpgp', 'reset', '-f']).decode('ascii')
        self.assertIn('Success! All data has been cleared and default PINs are set.', output)

