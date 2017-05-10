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
from enum import IntEnum, unique
from .driver_ccid import APDUError, SW_OK
from .util import AID, Tlv, parse_tlvs
from cryptography.utils import int_to_bytes, int_from_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
import struct
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
    TDES = 0x03
    RSA1024 = 0x06
    RSA2048 = 0x07
    ECCP256 = 0x11
    ECCP384 = 0x14


@unique
class SLOT(IntEnum):
    AUTHENTICATION = 0x9a
    CARD_MANAGEMENT = 0x9b
    SIGNATURE = 0x9c
    KEY_MANAGEMENT = 0x9d
    CARD_AUTH = 0x9e

    RETIRED1 = 0x82
    RETIRED2 = 0x83
    RETIRED3 = 0x84
    RETIRED4 = 0x85
    RETIRED5 = 0x86
    RETIRED6 = 0x87
    RETIRED7 = 0x88
    RETIRED8 = 0x89
    RETIRED9 = 0x8a
    RETIRED10 = 0x8b
    RETIRED11 = 0x8c
    RETIRED12 = 0x8d
    RETIRED13 = 0x8e
    RETIRED14 = 0x8f
    RETIRED15 = 0x90
    RETIRED16 = 0x91
    RETIRED17 = 0x92
    RETIRED18 = 0x93
    RETIRED19 = 0x94
    RETIRED20 = 0x95

    ATTESTATION = 0xf9


@unique
class OBJ(IntEnum):
    CAPABILITY = 0x5fc107
    CHUID = 0x5fc102
    AUTHENTICATION = 0x5fc105  # cert for 9a key
    FINGERPRINTS = 0x5fc103
    SECURITY = 0x5fc106
    FACIAL = 0x5fc108
    PRINTED = 0x5fc109
    SIGNATURE = 0x5fc10a  # cert for 9c key
    KEY_MANAGEMENT = 0x5fc10b  # cert for 9d key
    CARD_AUTH = 0x5fc101  # cert for 9e key
    DISCOVERY = 0x7e
    KEY_HISTORY = 0x5fc10c
    IRIS = 0x5fc121

    RETIRED1 = 0x5fc10d
    RETIRED2 = 0x5fc10e
    RETIRED3 = 0x5fc10f
    RETIRED4 = 0x5fc110
    RETIRED5 = 0x5fc111
    RETIRED6 = 0x5fc112
    RETIRED7 = 0x5fc113
    RETIRED8 = 0x5fc114
    RETIRED9 = 0x5fc115
    RETIRED10 = 0x5fc116
    RETIRED11 = 0x5fc117
    RETIRED12 = 0x5fc118
    RETIRED13 = 0x5fc119
    RETIRED14 = 0x5fc11a
    RETIRED15 = 0x5fc11b
    RETIRED16 = 0x5fc11c
    RETIRED17 = 0x5fc11d
    RETIRED18 = 0x5fc11e
    RETIRED19 = 0x5fc11f
    RETIRED20 = 0x5fc120

    ATTESTATION = 0x5fff01

    @classmethod
    def from_slot(cls, slot):
        return getattr(cls, SLOT(slot).name)


@unique
class TAG(IntEnum):
    DYN_AUTH = 0x7c
    ALGOS_SUPPORTED = 0xac
    OBJ_ID = 0x5c
    OBJ_DATA = 0x53
    ALGO = 0x80
    PIN_POLICY = 0xaa
    TOUCH_POLICY = 0xab


@unique
class DYN_AUTH(IntEnum):
    WITNESS = 0x80
    CHALLENGE = 0x81
    RESPONSE = 0x82


@unique
class PIN_POLICY(IntEnum):
    DEFAULT = 0x0
    NEVER = 0x1
    ONCE = 0x2
    ALWAYS = 0x3


@unique
class TOUCH_POLICY(IntEnum):
    DEFAULT = 0x0
    NEVER = 0x1
    ALWAYS = 0x2
    CACHED = 0x3


@unique
class SW(IntEnum):
    NO_SPACE = 0x6a84
    COMMAND_ABORTED = 0x6f00
    MORE_DATA = 0x61
    INVALID_INSTRUCTION = 0x6d00


PIN = 0x80
PUK = 0x81


def _pack_pin(pin):
    if isinstance(pin, six.text_type):
        pin = pin.encode('utf8')
    if len(pin) > 8:
        raise ValueError('PIN too large (max 8 bytes, was %d)' % len(pin))
    return pin.ljust(8, b'\xff')


def _get_key_data(key):
    if isinstance(key, rsa.RSAPrivateKey):
        if key.public_key().public_numbers().e != 65537:
            raise ValueError('Unsupported exponent!')

        if key.key_size == 1024:
            algo = ALGO.RSA1024
            l = 64
        elif key.key_size == 2048:
            algo = ALGO.RSA2048
            l = 128
        else:
            raise ValueError('Unsupported RSA key size!')

        priv = key.private_numbers()
        data = Tlv(0x01, int_to_bytes(priv.p, l)) + \
            Tlv(0x02, int_to_bytes(priv.q, l)) + \
            Tlv(0x03, int_to_bytes(priv.dmp1, l)) + \
            Tlv(0x04, int_to_bytes(priv.dmq1, l)) + \
            Tlv(0x05, int_to_bytes(priv.iqmp, l))
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP256R1):
            algo = ALGO.ECCP256
            l = 32
        elif isinstance(key.curve, ec.SECP384R1):
            algo = ALGO.ECCP384
            l = 48
        else:
            raise ValueError('Unsupported elliptic curve!')
        priv = key.private_numbers()
        data = Tlv(0x06, int_to_bytes(priv.private_value, l))
    else:
        raise ValueError('Unsupported key type!')
    return algo, data


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

        if check is None:
            return resp, sw
        elif sw != check:
            raise APDUError(resp, sw)

        return resp

    def _read_version(self):
        return tuple(six.iterbytes(self.send_apdu(INS.GET_VERSION)))

    def verify(self, pin):
        self.send_apdu(INS.VERIFY, 0, PIN, _pack_pin(pin))

    def change_pin(self, old_pin, new_pin):
        self.send_apdu(INS.CHANGE_REFERENCE, 0, PIN,
                       _pack_pin(old_pin) + _pack_pin(new_pin))

    def change_puk(self, old_puk, new_puk):
        self.send_apdu(INS.CHANGE_REFERENCE, 0, PUK,
                       _pack_pin(old_puk) + _pack_pin(new_puk))

    def unblock_pin(self, puk, new_pin):
        self.send_apdu(INS.RESET_RETRY, 0, PIN,
                       _pack_pin(puk) + _pack_pin(new_pin))

    def set_pin_retries(self, pin_retries, puk_retries):
        self.send_apdu(INS.SET_PIN_RETRIES, pin_retries, puk_retries)

    def authenticate(self, key):
        ct1 = self.send_apdu(INS.AUTHENTICATE, ALGO.TDES, SLOT.CARD_MANAGEMENT,
                             Tlv(TAG.DYN_AUTH, Tlv(DYN_AUTH.WITNESS)))[4:12]
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend)
        decryptor = cipher.decryptor()
        pt1 = decryptor.update(ct1) + decryptor.finalize()

        ct2 = os.urandom(8)
        pt2 = self.send_apdu(INS.AUTHENTICATE, ALGO.TDES, SLOT.CARD_MANAGEMENT,
                             Tlv(TAG.DYN_AUTH,
                                 Tlv(DYN_AUTH.WITNESS, pt1) +
                                 Tlv(DYN_AUTH.CHALLENGE, ct2)
                                 ))[4:12]

        encryptor = cipher.encryptor()
        pt2_cmp = encryptor.update(ct2) + encryptor.finalize()
        if not bytes_eq(pt2, pt2_cmp):
            raise ValueError('Device challenge did not match!')

    def set_mgm_key(self, new_key, touch=False):
        self.send_apdu(INS.SET_MGMKEY, 0xff, 0xfe if touch else 0xff,
                       bytes([ALGO.TDES]) + Tlv(SLOT.CARD_MANAGEMENT, new_key))

    def reset(self):
        _, sw = self.send_apdu(INS.VERIFY, 0, PIN, check=None)
        if sw >> 4 == 0x63c:
            tries = sw & 0xf
            print('Tries: %d' % tries)
            for _ in range(tries):
                self.send_apdu(INS.VERIFY, 0, PIN, _pack_pin(''), check=None)
        _, sw = self.send_apdu(INS.RESET_RETRY, 0, PIN, _pack_pin('')*2,
                               check=None)
        if sw >> 4 == 0x63c:
            tries = sw & 0xf
            print('Tries: %d' % tries)
            for _ in range(tries):
                self.send_apdu(INS.RESET_RETRY, 0, PIN, _pack_pin('')*2,
                               check=None)
        self.send_apdu(INS.RESET)

    def get_data(self, object_id):
        id_bytes = struct.pack(b'>I', object_id).lstrip(b'\0')
        tlv = Tlv(self.send_apdu(INS.GET_DATA, 0x3f, 0xff, Tlv(0x5c, id_bytes)))
        return tlv.value

    def put_data(self, object_id, data):
        id_bytes = struct.pack(b'>I', object_id).lstrip(b'\0')
        self.send_apdu(INS.PUT_DATA, 0x3f, 0xff, Tlv(0x5c, id_bytes) +
                       Tlv(0x53, data))

    def generate_key(self, slot, algorithm, pin_policy=PIN_POLICY.DEFAULT,
                     touch_policy=TOUCH_POLICY.DEFAULT):
        data = Tlv(TAG.ALGOS_SUPPORTED, Tlv(TAG.ALGO, bytes([algorithm])))
        if pin_policy:
            data += Tlv(TAG.PIN_POLICY, bytes([pin_policy]))
        if touch_policy:
            data += Tlv(TAG.TOUCH_POLICY, bytes([touch_policy]))
        resp = self.send_apdu(INS.GENERATE_ASYMMETRIC, 0, slot, data)
        if algorithm in [ALGO.RSA1024, ALGO.RSA2048]:
            data = parse_tlvs(Tlv(resp[1:]).value)
            return rsa.RSAPublicNumbers(
                int_from_bytes(data[1].value, 'big'),
                int_from_bytes(data[0].value, 'big')
            ).public_key(default_backend())
        else:
            curve = ec.SECP256R1 if algorithm == ALGO.ECCP256 else ec.SECP384R1
            return ec.EllipticCurvePublicNumbers.from_encoded_point(
                curve(),
                resp[5:]
            ).public_key(default_backend())
        raise ValueError('Invalid algorithm!')

    def import_key(self, slot, key, pin_policy=PIN_POLICY.DEFAULT,
                   touch_policy=TOUCH_POLICY.DEFAULT):
        algorithm, data = _get_key_data(key)
        if pin_policy:
            data += Tlv(TAG.PIN_POLICY, bytes([pin_policy]))
        if touch_policy:
            data += Tlv(TAG.TOUCH_POLICY, bytes([touch_policy]))
        self.send_apdu(INS.IMPORT_KEY, algorithm, slot, data)

    def import_certificate(self, slot, certificate):
        # TODO: compression?
        cert_data = certificate.public_bytes(Encoding.DER)
        data = Tlv(0x70, cert_data) + Tlv(0x71, b'\0') + Tlv(0xfe)
        self.put_data(OBJ.from_slot(slot), data)

    def sign_data(self, slot, algorithm, message):
        if algorithm == ALGO.RSA1024:
            l = 128
        elif algorithm == ALGO.RSA2048:
            l = 256
        elif algorithm == ALGO.ECCP256:
            l = 32
        elif algorithm == ALGO.ECCP384:
            l = 48
        if len(message) > l:
            raise ValueError('Message too long!')

        data = Tlv(0x7c, Tlv(0x82) + Tlv(0x81, message))

        self.send_apdu(INS.AUTHENTICATE, algorithm, slot, data)
