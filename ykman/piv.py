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


from enum import IntEnum, unique
from .driver_ccid import APDUError, SW_OK
from .util import AID, Tlv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.backends import default_backend
import six
import os


@unique
class INS(IntEnum):
    VERIFY = 0x20
    CHANGE_REFERENCE = 0x24
    RESET_RETRY = 0x2c
    GENERATE_ASYMMETRIC = 0x47
    AUTHENTICATE = 0x87
    SEND_REMAINING = 0xc0
    GET_DATA = 0xcb
    PUT_DATA = 0xdb
    SET_MGMKEY = 0xff
    IMPORT_KEY = 0xfe
    GET_VERSION = 0xfd
    RESET = 0xfb
    SET_PIN_RETRIES = 0xfa
    ATTEST = 0xf9


@unique
class ALGO(IntEnum):
    TDES = 0x03,
    RSA1024 = 0x06,
    RSA2048 = 0x07,
    ECCP256 = 0x11,
    ECCP384 = 0x14


@unique
class SLOT(IntEnum):
    AUTHENTICATION = 0x9a,
    CARDMGM = 0x9b,
    SIGNATURE = 0x9c,
    KEYMGM = 0x9d,
    CARDAUTH = 0x9e


@unique
class SW(IntEnum):
    NO_SPACE = 0x6a84
    COMMAND_ABORTED = 0x6f00
    MORE_DATA = 0x61
    INVALID_INSTRUCTION = 0x6d00


def _pack_pin(pin):
    if isinstance(pin, six.text_type):
        pin = pin.encode('utf8')
    if len(pin) > 8:
        raise ValueError('PIN too large (max 8 bytes, was %d)' % len(pin))
    return pin.ljust(8, b'\xff')


class PivController(object):

    def __init__(self, driver):
        driver.select(AID.PIV)
        self._driver = driver
        self._version = self._read_version()

    @property
    def version(self):
        return self._version

    def send_apdu(self, ins, p1=0, p2=0, data=b'', check=SW_OK):
        while len(data) > 0xff:
            self._driver.send_apdu(0x10, ins, p1, p2, data[:0xff])
            data = data[0xff:]
        resp, sw = self._driver.send_apdu(0, ins, p1, p2, data, check=None)

        while (sw >> 8) == SW.MORE_DATA:
            more, sw = self._driver.send_apdu(
                0, INS.SEND_REMAINING, 0, 0, b'', check=None)
            resp += more

        if sw != check:
            raise APDUError(resp, sw)

        return resp

    def _read_version(self):
        return tuple(six.iterbytes(self.send_apdu(INS.GET_VERSION)))

    def verify(self, pin):
        self.send_apdu(INS.VERIFY, 0, 0x80, _pack_pin(pin))

    def change_pin(self, old_pin, new_pin):
        self.send_apdu(INS.CHANGE_REFERENCE, 0, 0x80,
                       _pack_pin(old_pin) + _pack_pin(new_pin))

    def change_puk(self, old_puk, new_puk):
        self.send_apdu(INS.CHANGE_REFERENCE, 0, 0x81,
                       _pack_pin(old_puk) + _pack_pin(new_puk))

    def unblock_pin(self, puk, new_pin):
        self.send_apdu(INS.RESET_RETRY, 0, 0x80,
                       _pack_pin(puk) + _pack_pin(new_pin))

    def authenticate(self, key):
        ct1 = self.send_apdu(INS.AUTHENTICATE, ALGO.TDES, SLOT.CARDMGM,
                             Tlv(0x7c, Tlv(0x80)))[4:12]
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend)
        decryptor = cipher.decryptor()
        pt1 = decryptor.update(ct1) + decryptor.finalize()

        ct2 = os.urandom(8)
        pt2 = self.send_apdu(INS.AUTHENTICATE, ALGO.TDES, SLOT.CARDMGM,
                             Tlv(0x7c, Tlv(0x80, pt1) + Tlv(0x81, ct2)))[4:12]

        encryptor = cipher.encryptor()
        pt2_cmp = encryptor.update(ct2) + encryptor.finalize()
        if not bytes_eq(pt2, pt2_cmp):
            raise ValueError('Device challenge did not match!')

    def set_mgm_key(self, new_key, touch=False):
        self.send_apdu(INS.SET_MGMKEY, 0xff, 0xfe if touch else 0xff,
                       bytes([ALGO.TDES]) + Tlv(SLOT.CARDMGM, new_key))
