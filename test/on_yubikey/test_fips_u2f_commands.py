import unittest

from fido2.hid import (CTAPHID)
from ykman.util import (TRANSPORT)
from ykman.driver_fido import (FIPS_U2F_CMD)
from .util import (DestructiveYubikeyTestCase, is_fips, open_device)


HID_CMD = 0x03


@unittest.skipIf(not is_fips(), 'FIPS YubiKey required.')
class TestFipsU2fCommands(DestructiveYubikeyTestCase):

    def test_echo_command(self):
        dev = open_device(transports=TRANSPORT.FIDO)

        res = dev.driver._dev.call(
            CTAPHID.MSG,
            [*[0, FIPS_U2F_CMD.ECHO], 0, 0, *[0, 0, 6], *b'012345'])

        self.assertEqual(res, b'012345\x90\x00')

    def test_pin_commands(self):
        # Assumes PIN is 012345 or not set at beginning of test
        # Sets PIN to 012345

        dev = open_device(transports=TRANSPORT.FIDO)

        verify_res1 = dev.driver._dev.call(
            CTAPHID.MSG,
            [*[0, FIPS_U2F_CMD.VERIFY_PIN], 0, 0, *[0, 0, 6], *b'012345'])

        if verify_res1 == b'\x90\x90':
            res = dev.driver._dev.call(
                CTAPHID.MSG,
                [*[0, FIPS_U2F_CMD.SET_PIN], 0, 0,
                 *[0, 0, 13], *[6, *b'012345', *b'012345']])
        else:
            res = dev.driver._dev.call(
                CTAPHID.MSG,
                [*[0, FIPS_U2F_CMD.SET_PIN], 0, 0,
                 *[0, 0, 7], *[6, *b'012345']])

        verify_res2 = dev.driver._dev.call(
            CTAPHID.MSG,
            [*[0, FIPS_U2F_CMD.VERIFY_PIN], 0, 0, *[0, 0, 6], *b'543210'])

        verify_res3 = dev.driver._dev.call(
            CTAPHID.MSG,
            [*[0, FIPS_U2F_CMD.VERIFY_PIN], 0, 0, *[0, 0, 6], *b'012345'])

        self.assertIn(verify_res1, [b'\x90\x00', b'\x69\x86'])  # OK / not set
        self.assertEqual(res,         b'\x90\x00')  # Success
        self.assertEqual(verify_res2, b'\x63\xc0')  # Incorrect PIN
        self.assertEqual(verify_res3, b'\x90\x00')  # Success

    def test_reset_command(self):
        dev = open_device(transports=TRANSPORT.FIDO)

        res = dev.driver._dev.call(
            CTAPHID.MSG, [*[0, FIPS_U2F_CMD.RESET], 0, 0])

        # 0x6985: Touch required
        # 0x6986: Power cycle required
        # 0x9000: Success
        self.assertIn(res, [b'\x69\x85', b'\x69\x86', b'\x90\x00'])

    def test_verify_fips_mode_command(self):
        dev = open_device(transports=TRANSPORT.FIDO)

        res = dev.driver._dev.call(
            CTAPHID.MSG, [*[0, FIPS_U2F_CMD.VERIFY_FIPS_MODE], 0, 0])

        # 0x6a81: Function not supported (PIN not set - not FIPS mode)
        # 0x9000: Success (PIN set - FIPS mode)
        self.assertIn(res, [b'\x6a\x81', b'\x90\x00'])
