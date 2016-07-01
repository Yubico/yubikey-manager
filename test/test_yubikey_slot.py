import unittest
from subprocess import check_output
from ykman.util import list_yubikeys 

class NotOneYubiKeyError(Exception):
    pass

class TestSlotProgramming(unittest.TestCase):
    
    @classmethod
    def setUpClass(self):
        if len(list_yubikeys()) != 1:
            raise NotOneYubiKeyError("To run these tests, a single YubiKey must be connected.")

    def test_ykman_info(self):
        info = check_output(['ykman', 'info']).decode('ascii')
        self.assertIn('Device name:', info) 
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info) 
     
    def test_ykman_slot_info(self):
        info = check_output(['ykman', 'slot', 'info']).decode('ascii')
        self.assertIn('Slot 1:', info) 
        self.assertIn('Slot 2:', info)

    def test_ykman_program_otp_slot_2(self):
        self._delete_slot_2()
        output = check_output(['ykman', 'slot', 'otp', '2', '-f']).decode('ascii')
        self.assertIn('Using serial as public ID:', output)
        self.assertIn('Using a randomly generated private ID:', output)
        self.assertIn('Using a randomly generated secret key:', output)
        self._check_slot_2_programmed()
    
    def test_ykman_program_chalresp_slot_2(self):
        self._delete_slot_2()
        output = check_output(['ykman', 'slot', 'chalresp', '2', '-f']).decode('ascii')
        self.assertIn('Using a randomly generated key.', output)
        self._check_slot_2_programmed()

    def test_ykman_program_hotp_slot_2(self):
        self._delete_slot_2()
        output = check_output(['ykman', 'slot', 'hotp', '2', '27KIZZE3SD7GE2FVJJBAXEI3I6RRTPGM', '-f']).decode('ascii')
        self.assertIn('Programming HOTP credential in slot 2...', output)
        self._check_slot_2_programmed()

    def test_ykman_program_static_slot_2(self):
        self._delete_slot_2()
        output = check_output(['ykman', 'slot', 'static', '2', 'higngdukgerjktbbikrhirngtlkkttkb', '-f']).decode('ascii')
        self.assertIn('Setting static password in slot 2...', output)
        self._check_slot_2_programmed()

    def test_ykman_swap_slots(self):
        output = check_output(['ykman', 'slot', 'swap', '-f']).decode('ascii')
        self.assertIn('Swapping slots...', output)
        output = check_output(['ykman', 'slot', 'swap', '-f']).decode('ascii')
        self.assertIn('Swapping slots...', output)

    def _delete_slot_2(self):
        output = check_output(['ykman', 'slot', 'delete', '2', '-f']).decode('ascii')
        self.assertIn('Deleting slot: 2...', output)
        status = check_output(['ykman', 'slot', 'info']).decode('ascii')
        self.assertIn('Slot 2: empty', status)
    
    def _check_slot_2_programmed(self):
        status = check_output(['ykman', 'slot', 'info']).decode('ascii')
        self.assertIn('Slot 2: programmed', status)

