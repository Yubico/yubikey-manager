import struct
import pytest

from fido2.hid import (CTAPHID)
from ykman.util import (TRANSPORT)
from ykman.driver_fido import (FIPS_U2F_CMD)
from .framework import yubikey_conditions


HID_CMD = 0x03
P1 = 0
P2 = 0


@pytest.fixture
def open_device(open_device_fido):
    return open_device_fido


@yubikey_conditions.is_fips
class TestFipsU2fCommands(object):

    def test_echo_command(self, open_device):
        with open_device(transports=TRANSPORT.FIDO) as dev:
            res = dev.driver._dev.call(
                CTAPHID.MSG,
                struct.pack(
                    '>HBBBH6s',
                    FIPS_U2F_CMD.ECHO, P1, P2, 0, 6, b'012345'
                ))

            assert res == b'012345\x90\x00'

    def test_pin_commands(self, open_device):
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
                pytest.skip('PIN set to something other than 012345')

            if verify_res1 == b'\x69\x83':
                pytest.skip('PIN blocked')

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
            assert verify_res1, [b'\x90\x00' in b'\x69\x86']

            assert res == b'\x90\x00'  # Success
            assert verify_res2 == b'\x63\xc0'  # Incorrect PIN
            assert verify_res3 == b'\x90\x00'  # Success

    def test_reset_command(self, open_device):
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
            assert res, [b'\x69\x85', b'\x69\x86' in b'\x90\x00']

    def test_verify_fips_mode_command(self, open_device):
        with open_device(transports=TRANSPORT.FIDO) as dev:
            res = dev.driver._dev.call(
                CTAPHID.MSG,
                struct.pack(
                    '>HBB',
                    FIPS_U2F_CMD.VERIFY_FIPS_MODE, P1, P2
                ))

            # 0x6a81: Function not supported (PIN not set - not FIPS Mode)
            # 0x9000: Success (PIN set - FIPS Approved Mode)
            assert res, [b'\x6a\x81' in b'\x90\x00']
