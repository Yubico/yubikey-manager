import struct
import unittest

from fido2.hid import (CTAPHID)
from ykman.util import (TRANSPORT)
from ykman.driver_fido import (FIPS_U2F_CMD)
from .framework import device_test_suite, yubikey_conditions


HID_CMD = 0x03
P1 = 0
P2 = 0


@device_test_suite(TRANSPORT.FIDO)
def additional_tests(open_device):

    @yubikey_conditions.is_fips
    class TestFipsU2fCommands(unittest.TestCase):

        def test_echo_command(self):
            with open_device(transports=TRANSPORT.FIDO) as dev:
                res = dev.driver._dev.call(
                    CTAPHID.MSG,
                    struct.pack(
                        '>HBBBH6s',
                        FIPS_U2F_CMD.ECHO, P1, P2, 0, 6, b'012345'
                    ))

                self.assertEqual(res, b'012345\x90\x00')

        def test_pin_commands(self):
            # Assumes PIN is 012345 or not set at beginning of test
            # Sets PIN to 012345

            with open_device(transports=TRANSPORT.FIDO) as dev:
                verify_res1 = dev.driver._dev.call(
                    CTAPHID.MSG,
                    struct.pack(
                        '>HBBBH6s',
                        FIPS_U2F_CMD.VERIFY_PIN, P1, P2, 0, 6, b'012345'
                    ))

                if verify_res1 == b'\x63\xc0':
                    self.skipTest('PIN set to something other than 012345')

                if verify_res1 == b'\x69\x83':
                    self.skipTest('PIN blocked')

                if verify_res1 == b'\x90\x00':
                    res = dev.driver._dev.call(
                        CTAPHID.MSG,
                        struct.pack(
                            '>HBBBHB6s6s',
                            FIPS_U2F_CMD.SET_PIN, P1, P2,
                            0, 13, 6, b'012345', b'012345'
                        ))
                else:
                    res = dev.driver._dev.call(
                        CTAPHID.MSG,
                        struct.pack(
                            '>HBBBHB6s',
                            FIPS_U2F_CMD.SET_PIN, P1, P2, 0, 7, 6, b'012345'
                        ))

                verify_res2 = dev.driver._dev.call(
                    CTAPHID.MSG,
                    struct.pack(
                        '>HBBBH6s',
                        FIPS_U2F_CMD.VERIFY_PIN, P1, P2, 0, 6, b'543210'
                    ))

                verify_res3 = dev.driver._dev.call(
                    CTAPHID.MSG,
                    struct.pack(
                        '>HBBBH6s',
                        FIPS_U2F_CMD.VERIFY_PIN, P1, P2, 0, 6, b'012345'
                    ))

                # OK/not set
                self.assertIn(verify_res1, [b'\x90\x00', b'\x69\x86'])

                self.assertEqual(res,         b'\x90\x00')  # Success
                self.assertEqual(verify_res2, b'\x63\xc0')  # Incorrect PIN
                self.assertEqual(verify_res3, b'\x90\x00')  # Success

        def test_reset_command(self):
            with open_device(transports=TRANSPORT.FIDO) as dev:
                res = dev.driver._dev.call(
                    CTAPHID.MSG,
                    struct.pack(
                        '>HBB',
                        FIPS_U2F_CMD.RESET, P1, P2
                    ))

                # 0x6985: Touch required
                # 0x6986: Power cycle required
                # 0x9000: Success
                self.assertIn(res, [b'\x69\x85', b'\x69\x86', b'\x90\x00'])

        def test_verify_fips_mode_command(self):
            with open_device(transports=TRANSPORT.FIDO) as dev:
                res = dev.driver._dev.call(
                    CTAPHID.MSG,
                    struct.pack(
                        '>HBB',
                        FIPS_U2F_CMD.VERIFY_FIPS_MODE, P1, P2
                    ))

                # 0x6a81: Function not supported (PIN not set - not FIPS Mode)
                # 0x9000: Success (PIN set - FIPS Approved Mode)
                self.assertIn(res, [b'\x6a\x81', b'\x90\x00'])

    return [TestFipsU2fCommands]
