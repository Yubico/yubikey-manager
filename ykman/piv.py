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
from cryptography import x509
from cryptography.utils import int_to_bytes, int_from_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from collections import OrderedDict
from threading import Timer
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

    @classmethod
    def from_public_key(cls, key):
        if isinstance(key, rsa.RSAPublicKey):
            return getattr(cls, 'RSA%d' % key.key_size)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            curve_name = key.curve.name
            if curve_name == 'secp256r1':
                return cls.ECCP256
            elif curve_name == 'secp384r1':
                return cls.ECCP384
        raise ValueError('Unsupported key type!')

    @classmethod
    def from_string(cls, algorithm):
        if algorithm == 'RSA1024':
            return cls.RSA1024
        if algorithm == 'RSA2048':
            return cls.RSA2048
        if algorithm == 'ECCP256':
            return cls.ECCP256
        if algorithm == 'ECCP384':
            return cls.ECCP384
        raise ValueError('Unsupported algorithm!')


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

    PIVMAN_DATA = 0x5fff00
    ATTESTATION = 0x5fff01

    @classmethod
    def from_slot(cls, slot):
        return getattr(cls, SLOT(slot).name)


@unique
class TAG(IntEnum):
    DYN_AUTH = 0x7c
    OBJ_ID = 0x5c
    OBJ_DATA = 0x53
    CERTIFICATE = 0x70
    CERT_INFO = 0x71
    ALGO = 0x80
    PIN_POLICY = 0xaa
    TOUCH_POLICY = 0xab
    LRC = 0xfe


@unique
class PIN_POLICY(IntEnum):
    DEFAULT = 0x0
    NEVER = 0x1
    ONCE = 0x2
    ALWAYS = 0x3

    @classmethod
    def from_string(cls, pin_policy):
        if pin_policy == 'DEFAULT':
            return cls.DEFAULT
        if pin_policy == 'NEVER':
            return cls.NEVER
        if pin_policy == 'ONCE':
            return cls.ONCE
        if pin_policy == 'ALWAYS':
            return cls.ALWAYS
        raise ValueError('Unsupported pin policy!')


@unique
class TOUCH_POLICY(IntEnum):
    DEFAULT = 0x0
    NEVER = 0x1
    ALWAYS = 0x2
    CACHED = 0x3

    @classmethod
    def from_string(cls, touch_policy):
        if touch_policy == 'DEFAULT':
            return cls.DEFAULT
        if touch_policy == 'NEVER':
            return cls.NEVER
        if touch_policy == 'ALWAYS':
            return cls.ALWAYS
        if touch_policy == 'CACHED':
            return cls.CACHED
        raise ValueError('Unsupported touch policy!')


@unique
class SW(IntEnum):
    NO_SPACE = 0x6a84
    COMMAND_ABORTED = 0x6f00
    MORE_DATA = 0x61
    INVALID_INSTRUCTION = 0x6d00
    NOT_FOUND = 0x6a82
    ACCESS_DENIED = 0x6982
    AUTHENTICATION_BLOCKED = 0x6983


PIN = 0x80
PUK = 0x81

# 010203040506070801020304050607080102030405060708
DEFAULT_MANAGEMENT_KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08' \
    + b'\x01\x02\x03\x04\x05\x06\x07\x08' \
    + b'\x01\x02\x03\x04\x05\x06\x07\x08'


def _parse_tlv_dict(data):
    return dict((tlv.tag, tlv.value) for tlv in parse_tlvs(data))


def _pack_pin(pin):
    if isinstance(pin, six.text_type):
        pin = pin.encode('utf8')
    if len(pin) > 8:
        raise ValueError('PIN/PUK too large (max 8 bytes, was %d)' % len(pin))
    return pin.ljust(8, b'\xff')


def _get_key_data(key):
    if isinstance(key, rsa.RSAPrivateKey):
        if key.public_key().public_numbers().e != 65537:
            raise ValueError('Unsupported RSA exponent!')

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


def _dummy_key(algorithm):
    if algorithm == ALGO.RSA1024:
        return rsa.generate_private_key(65537, 1024, default_backend())
    if algorithm == ALGO.RSA2048:
        return rsa.generate_private_key(65537, 2048, default_backend())
    if algorithm == ALGO.ECCP256:
        return ec.generate_private_key(ec.SECP256R1(), default_backend())
    if algorithm == ALGO.ECCP384:
        return ec.generate_private_key(ec.SECP384R1(), default_backend())
    raise ValueError('Unsupported algorithm!')


def _pkcs1_15_pad(algorithm, message):
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(message)
    t = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05' + \
        b'\x00\x04\x20' + h.finalize()
    em_len = 128 if algorithm == ALGO.RSA1024 else 256
    f_len = em_len - len(t) - 3
    return b'\0\1' + b'\xff' * f_len + b'\0' + t


_sign_len_conditions = {
    ALGO.RSA1024: lambda l: l == 128,
    ALGO.RSA2048: lambda l: l == 256,
    ALGO.ECCP256: lambda l: l <= 32,
    ALGO.ECCP384: lambda l: l <= 48
}


_decrypt_len_conditions = {
    ALGO.RSA1024: lambda l: l == 128,
    ALGO.RSA2048: lambda l: l == 256,
    ALGO.ECCP256: lambda l: l == 65,
    ALGO.ECCP384: lambda l: l == 97
}


def _derive_key(pin, salt):
    kdf = PBKDF2HMAC(hashes.SHA1(), 24, salt, 10000, default_backend())
    return kdf.derive(pin.encode('utf-8'))


class PivmanData(object):

    def __init__(self, raw_data=Tlv(0x80)):
        data = _parse_tlv_dict(Tlv(raw_data).value)
        self._flags = struct.unpack(
            '>B', data[0x81])[0] if 0x81 in data else None
        self.salt = data.get(0x82)
        self.pin_timestamp = struct.unpack('>I', data[0x83]) \
            if 0x83 in data else None

    def _get_flag(self, mask):
        return bool((self._flags or 0) & mask)

    def _set_flag(self, mask, value):
        if value:
            self._flags = (self._flags or 0) | mask
        elif self._flags is not None:
            self._flags &= ~mask

    @property
    def puk_blocked(self):
        return self._get_flag(0x01)

    @puk_blocked.setter
    def puk_blocked(self, value):
        self._set_flag(0x01, value)

    def get_bytes(self):
        data = b''
        if self._flags is not None:
            data += Tlv(0x81, struct.pack('>B', self._flags))
        if self.salt is not None:
            data += Tlv(0x82, self.salt)
        if self.pin_timestamp is not None:
            data += Tlv(0x83, struct.pack('>I', self.pin_timestamp))
        return Tlv(0x80, data)


class PivController(object):

    def __init__(self, driver):
        driver.select(AID.PIV)
        self._authenticated = False
        self._driver = driver
        self._version = self._read_version()
        try:
            self._pivman_data = PivmanData(self.get_data(OBJ.PIVMAN_DATA))
        except APDUError:
            self._pivman_data = PivmanData()

    @property
    def version(self):
        return self._version

    @property
    def has_derived_key(self):
        return self._pivman_data.salt is not None

    @property
    def puk_blocked(self):
        return self._pivman_data.puk_blocked

    def send_cmd(self, ins, p1=0, p2=0, data=b'', check=SW_OK):
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
        return tuple(six.iterbytes(self.send_cmd(INS.GET_VERSION)))

    def verify(self, pin, touch_callback=None):
        try:
            self.send_cmd(INS.VERIFY, 0, PIN, _pack_pin(pin))
        except APDUError:
            raise ValueError(
                'Pin verification failed. {} tries left.'.format(
                        self.get_pin_tries()))
        if self.has_derived_key and not self._authenticated:
            self.authenticate(
                _derive_key(pin, self._pivman_data.salt), touch_callback)

    def change_pin(self, old_pin, new_pin):
        self.send_cmd(INS.CHANGE_REFERENCE, 0, PIN,
                      _pack_pin(old_pin) + _pack_pin(new_pin))
        if self.has_derived_key:
            if not self._authenticated:
                self.authenticate(_derive_key(old_pin, self._pivman_data.salt))
            self.use_derived_key(new_pin)

    def change_puk(self, old_puk, new_puk):
        self.send_cmd(INS.CHANGE_REFERENCE, 0, PUK,
                      _pack_pin(old_puk) + _pack_pin(new_puk))

    def unblock_pin(self, puk, new_pin):
        try:
            self.send_cmd(
                INS.RESET_RETRY, 0, PIN, _pack_pin(puk) + _pack_pin(new_pin))
        except APDUError as e:
            tries = self._parse_tries_left(e.sw)
            if tries == 0:
                raise ValueError('PUK is blocked.')
            raise ValueError('Unblock PIN failed, {} tries left.'.format(tries))

    def set_pin_retries(self, pin_retries, puk_retries):
        self.send_cmd(INS.SET_PIN_RETRIES, pin_retries, puk_retries)

    def use_derived_key(self, pin, touch=False):
        self.verify(pin)
        if not self.puk_blocked:
            self._block_puk()
            self._pivman_data.puk_blocked = True

        new_salt = os.urandom(16)
        new_key = _derive_key(pin, new_salt)
        self.send_cmd(INS.SET_MGMKEY, 0xff, 0xfe if touch else 0xff,
                      six.int2byte(ALGO.TDES) +
                      Tlv(SLOT.CARD_MANAGEMENT, new_key))
        self._pivman_data.salt = new_salt
        self.put_data(OBJ.PIVMAN_DATA, self._pivman_data.get_bytes())

    def set_pin_timestamp(self, timestamp):
        self._pivman_data.pin_timestamp = timestamp
        self.put_data(OBJ.PIVMAN_DATA, self._pivman_data.get_bytes())

    def authenticate(self, key, touch_callback=None):
        ct1 = self.send_cmd(INS.AUTHENTICATE, ALGO.TDES, SLOT.CARD_MANAGEMENT,
                            Tlv(TAG.DYN_AUTH, Tlv(0x80)))[4:12]
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend)
        decryptor = cipher.decryptor()
        pt1 = decryptor.update(ct1) + decryptor.finalize()
        ct2 = os.urandom(8)

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        pt2 = self.send_cmd(INS.AUTHENTICATE, ALGO.TDES, SLOT.CARD_MANAGEMENT,
                            Tlv(TAG.DYN_AUTH, Tlv(0x80, pt1) + Tlv(0x81, ct2))
                            )[4:12]

        if touch_callback is not None:
            touch_timer.cancel()

        encryptor = cipher.encryptor()
        pt2_cmp = encryptor.update(ct2) + encryptor.finalize()
        if not bytes_eq(pt2, pt2_cmp):
            raise ValueError('Device challenge did not match!')
        self._authenticated = True

    def set_mgm_key(self, new_key, touch=False):
        self.send_cmd(
            INS.SET_MGMKEY, 0xff, 0xfe if touch else 0xff,
            six.int2byte(ALGO.TDES) + Tlv(SLOT.CARD_MANAGEMENT, new_key))
        if self.has_derived_key:
            self._pivman_data.salt = None
            self.put_data(OBJ.PIVMAN_DATA, self._pivman_data.get_bytes())

    def get_pin_tries(self):
        """
        Returns the number of PIN retries left,
        0 PIN authentication blocked. Note that 15 is the highest
        value that will be returned even if remaining tries is higher.
        """
        try:
            # Verify without PIN gives number of tries left.
            _, sw = self.send_cmd(INS.VERIFY, 0, PIN)
        except APDUError as e:
            return self._parse_tries_left(e.sw)

    def _get_puk_tries(self):
        try:
            # A failed unblock pin will return number of PUK tries left,
            # but also uses one try.
            _, sw = self.send_cmd(INS.RESET_RETRY, 0, PIN, _pack_pin('')*2)
        except APDUError as e:
            return self._parse_tries_left(e.sw)

    def _parse_tries_left(self, sw):
        # Blocked, 0 tries left.
        if sw == SW.AUTHENTICATION_BLOCKED:
            return 0
        # YK4, NEO with PIV >= 1.0.4
        if 0x63c0 <= sw <= 0x63cf:
            return sw & 0xf
        # PIV applet < 1.04
        if 0x6300 <= sw & 0x63ff:
            return sw & 0xff
        raise ValueError('Failed reading remaining PIN/PUK tries!')

    def _block_pin(self):
        while self.get_pin_tries() > 0:
            self.send_cmd(INS.VERIFY, 0, PIN, _pack_pin(''), check=None)

    def _block_puk(self):
        while self._get_puk_tries() > 0:
            self.send_cmd(INS.RESET_RETRY, 0, PIN, _pack_pin('')*2, check=None)

    def reset(self):
        self._block_pin()
        self._block_puk()
        self.send_cmd(INS.RESET)

    def get_data(self, object_id):
        id_bytes = struct.pack(b'>I', object_id).lstrip(b'\0')
        tlv = Tlv(self.send_cmd(INS.GET_DATA, 0x3f, 0xff,
                                Tlv(TAG.OBJ_ID, id_bytes)))
        if tlv.tag != TAG.OBJ_DATA:
            raise ValueError('Wrong tag in response data!')
        return tlv.value

    def put_data(self, object_id, data):
        id_bytes = struct.pack(b'>I', object_id).lstrip(b'\0')
        self.send_cmd(INS.PUT_DATA, 0x3f, 0xff, Tlv(TAG.OBJ_ID, id_bytes) +
                      Tlv(TAG.OBJ_DATA, data))

    def generate_key(self, slot, algorithm, pin_policy=PIN_POLICY.DEFAULT,
                     touch_policy=TOUCH_POLICY.DEFAULT):
        data = Tlv(TAG.ALGO, six.int2byte(algorithm))
        if pin_policy:
            data += Tlv(TAG.PIN_POLICY, six.int2byte(pin_policy))
        if touch_policy:
            data += Tlv(TAG.TOUCH_POLICY, six.int2byte(touch_policy))
        data = Tlv(0xac, data)
        resp = self.send_cmd(INS.GENERATE_ASYMMETRIC, 0, slot, data)
        if algorithm in [ALGO.RSA1024, ALGO.RSA2048]:
            data = _parse_tlv_dict(Tlv(resp[1:]).value)
            return rsa.RSAPublicNumbers(
                int_from_bytes(data[0x82], 'big'),
                int_from_bytes(data[0x81], 'big')
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
            data += Tlv(TAG.PIN_POLICY, six.int2byte(pin_policy))
        if touch_policy:
            data += Tlv(TAG.TOUCH_POLICY, six.int2byte(touch_policy))
        self.send_cmd(INS.IMPORT_KEY, algorithm, slot, data)
        return algorithm

    def import_certificate(self, slot, certificate):
        cert_data = certificate.public_bytes(Encoding.DER)
        self.put_data(OBJ.from_slot(slot), Tlv(TAG.CERTIFICATE, cert_data) +
                      Tlv(TAG.CERT_INFO, b'\0') + Tlv(TAG.LRC))

    def read_certificate(self, slot):
        data = _parse_tlv_dict(self.get_data(OBJ.from_slot(slot)))
        if TAG.CERT_INFO in data:  # Not available in attestation slot
            if data[TAG.CERT_INFO] != b'\0':
                raise ValueError('Compressed certificates are not supported!')
        return x509.load_der_x509_certificate(data[TAG.CERTIFICATE],
                                              default_backend())

    def delete_certificate(self, slot):
        self.put_data(OBJ.from_slot(slot), b'')

    def attest(self, slot):
        return x509.load_der_x509_certificate(self.send_cmd(INS.ATTEST, slot),
                                              default_backend())

    def _raw_sign_decrypt(self, slot, algorithm, payload, condition):
        if not condition(len(payload.value)):
            raise ValueError('Input has invalid length!')

        data = Tlv(TAG.DYN_AUTH, Tlv(0x82) + payload)
        resp = self.send_cmd(INS.AUTHENTICATE, algorithm, slot, data)
        return Tlv(Tlv(resp).value).value

    def sign_raw(self, slot, algorithm, message):
        return self._raw_sign_decrypt(slot, algorithm, Tlv(0x81, message),
                                      _sign_len_conditions[algorithm])

    def decrypt_raw(self, slot, algorithm, message):
        return self._raw_sign_decrypt(slot, algorithm, Tlv(0x85, message),
                                      _decrypt_len_conditions[algorithm])

    # Not sure if these should go in this class or somewhere else

    def list_certificates(self):
        certs = OrderedDict()
        for slot in set(SLOT) - {SLOT.CARD_MANAGEMENT, SLOT.ATTESTATION}:
            try:
                certs[slot] = self.read_certificate(slot)
            except APDUError:
                pass
        return certs

    def update_chuid(self):
        self.put_data(
            OBJ.CHUID,
            Tlv(0x30, b'\xd4\xe7\x39\xda\x73\x9c\xed\x39\xce\x73\x9d\x83\x68'
                b'\x58\x21\x08\x42\x10\x84\x21\x38\x42\x10\xc3\xf5') +
            Tlv(0x34, os.urandom(16)) +
            Tlv(0x35, b'\x32\x30\x33\x30\x30\x31\x30\x31') +
            Tlv(0x3e) +
            Tlv(TAG.LRC)
        )

    def update_ccc(self):
        self.put_data(
            OBJ.CAPABILITY,
            Tlv(0xf0, b'\xa0\x00\x00\x01\x16\xff\x02' + os.urandom(14)) +
            Tlv(0xf1, b'\x21') +
            Tlv(0xf2, b'\x21') +
            Tlv(0xf3) +
            Tlv(0xf4, b'\x00') +
            Tlv(0xf5, b'\x10') +
            Tlv(0xf6) +
            Tlv(0xf7) +
            Tlv(0xfa) +
            Tlv(0xfb) +
            Tlv(0xfc) +
            Tlv(0xfd) +
            Tlv(TAG.LRC)
        )

    def sign_cert_builder(self, slot, algorithm, builder, touch_callback=None):
        dummy_key = _dummy_key(algorithm)
        cert = builder.sign(dummy_key, hashes.SHA256(), default_backend())
        message = cert.tbs_certificate_bytes

        if algorithm in (ALGO.RSA1024, ALGO.RSA2048):
            message = _pkcs1_15_pad(algorithm, message)
        elif algorithm in (ALGO.ECCP256, ALGO.ECCP384):
            h = hashes.Hash(hashes.SHA256(), default_backend())
            h.update(message)
            message = h.finalize()

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        sig = self.sign_raw(slot, algorithm, message)

        if touch_callback is not None:
            touch_timer.cancel()

        seq = parse_tlvs(Tlv(cert.public_bytes(Encoding.DER)).value)
        # Replace signature, add unused bits = 0
        seq[2] = Tlv(seq[2].tag, b'\0' + sig)
        # Re-assemble sequence
        der = Tlv(0x30, b''.join(seq))

        return x509.load_der_x509_certificate(der, default_backend())

    def sign_csr_builder(self, slot, public_key, builder, touch_callback=None):
        algorithm = ALGO.from_public_key(public_key)
        dummy_key = _dummy_key(algorithm)
        cert = builder.sign(dummy_key, hashes.SHA256(), default_backend())
        message = cert.tbs_certrequest_bytes

        if algorithm in (ALGO.RSA1024, ALGO.RSA2048):
            message = _pkcs1_15_pad(algorithm, message)
            dummy_bytes = dummy_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.PKCS1)
            pub_bytes = public_key.public_bytes(
                Encoding.DER, PublicFormat.PKCS1)
        elif algorithm in (ALGO.ECCP256, ALGO.ECCP384):
            h = hashes.Hash(hashes.SHA256(), default_backend())
            h.update(message)
            message = h.finalize()
            dummy_bytes = dummy_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            pub_bytes = public_key.public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        sig = self.sign_raw(slot, algorithm, message)

        if touch_callback is not None:
            touch_timer.cancel()

        seq = parse_tlvs(Tlv(cert.public_bytes(Encoding.DER)).value)
        # Replace public key
        seq[0] = seq[0].replace(dummy_bytes, pub_bytes)
        # Replace signature, add unused bits = 0
        seq[2] = Tlv(seq[2].tag, b'\0' + sig)
        # Re-assemble sequence
        der = Tlv(0x30, b''.join(seq))

        return x509.load_der_x509_csr(der, default_backend())
