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
from .device import YubiKey
from .driver_ccid import APDUError, SW
from .util import (
    AID, Tlv,
    is_cve201715361_vulnerable_firmware_version,
    ensure_not_cve201715361_vulnerable_firmware_version)
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.utils import int_to_bytes, int_from_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from collections import OrderedDict
from threading import Timer
import logging
import struct
import six
import os


logger = logging.getLogger(__name__)


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
        raise UnsupportedAlgorithm(
            'Unsupported key type: %s' % type(key), key=key)

    @classmethod
    def is_rsa(cls, algorithm_int):
        # Implemented as "not not RSA" to reduce risk of false negatives if
        # more algorithms are added
        return not (
            algorithm_int == cls.TDES
            or algorithm_int == cls.ECCP256
            or algorithm_int == cls.ECCP384
        )


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
    PIVMAN_PROTECTED_DATA = 0x5fc109  # Use slot for printed information.
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


@unique
class TOUCH_POLICY(IntEnum):
    DEFAULT = 0x0
    NEVER = 0x1
    ALWAYS = 0x2
    CACHED = 0x3


class AuthenticationFailed(Exception):
    def __init__(self, message, sw, applet_version):
        super(AuthenticationFailed, self).__init__(message)
        self.tries_left = (
            tries_left(sw, applet_version)
            if is_verify_fail(sw, applet_version)
            else None)


class AuthenticationBlocked(AuthenticationFailed):
    def __init__(self, message, sw):
        # Dummy applet_version since sw will always be "authentication blocked"
        super(AuthenticationBlocked, self).__init__(message, sw, ())


class BadFormat(Exception):
    def __init__(self, message, bad_value):
        super(BadFormat, self).__init__(message)
        self.bad_value = bad_value


class InvalidCertificate(Exception):
    def __init__(self, slot):
        super(InvalidCertificate, self).__init__(
            'Failed to parse certificate in slot {:x}'.format(slot))
        self.slot = slot


class KeypairMismatch(Exception):
    def __init__(self, slot, cert):
        super(KeypairMismatch, self).__init__(
            'The certificate does not match the private key in slot %s.' % slot)
        self.slot = slot
        self.cert = cert


class UnsupportedAlgorithm(Exception):
    def __init__(self, message, algorithm_id=None, key=None, ):
        super(UnsupportedAlgorithm, self).__init__(message)
        if algorithm_id is None and key is None:
            raise ValueError(
                'At least one of algorithm_id and key must be given.')

        self.algorithm_id = algorithm_id
        self.key = key


class WrongPin(AuthenticationFailed):
    def __init__(self, sw, applet_version):
        super(WrongPin, self).__init__(
            'Incorrect PIN', sw, applet_version)


class WrongPuk(AuthenticationFailed):
    def __init__(self, sw, applet_version):
        super(WrongPuk, self).__init__(
            'Incorrect PUK', sw, applet_version)


PIN = 0x80
PUK = 0x81

# 010203040506070801020304050607080102030405060708
DEFAULT_MANAGEMENT_KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08' \
    + b'\x01\x02\x03\x04\x05\x06\x07\x08' \
    + b'\x01\x02\x03\x04\x05\x06\x07\x08'


def _pack_pin(pin):
    if isinstance(pin, six.text_type):
        pin = pin.encode('utf8')
    if len(pin) > 8:
        raise BadFormat(
            'PIN/PUK too large (max 8 bytes, was %d)' % len(pin), pin)
    return pin.ljust(8, b'\xff')


def _get_key_data(key):
    if isinstance(key, rsa.RSAPrivateKey):
        if key.public_key().public_numbers().e != 65537:
            raise UnsupportedAlgorithm(
                'Unsupported RSA exponent: %d'
                % key.public_key().public_numbers().e,
                key=key)

        if key.key_size == 1024:
            algo = ALGO.RSA1024
            ln = 64
        elif key.key_size == 2048:
            algo = ALGO.RSA2048
            ln = 128
        else:
            raise UnsupportedAlgorithm(
                'Unsupported RSA key size: %d' % key.key_size, key=key)

        priv = key.private_numbers()
        data = Tlv(0x01, int_to_bytes(priv.p, ln)) + \
            Tlv(0x02, int_to_bytes(priv.q, ln)) + \
            Tlv(0x03, int_to_bytes(priv.dmp1, ln)) + \
            Tlv(0x04, int_to_bytes(priv.dmq1, ln)) + \
            Tlv(0x05, int_to_bytes(priv.iqmp, ln))
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP256R1):
            algo = ALGO.ECCP256
            ln = 32
        elif isinstance(key.curve, ec.SECP384R1):
            algo = ALGO.ECCP384
            ln = 48
        else:
            raise UnsupportedAlgorithm(
                    'Unsupported elliptic curve: %s', key.curve, key=key)
        priv = key.private_numbers()
        data = Tlv(0x06, int_to_bytes(priv.private_value, ln))
    else:
        raise UnsupportedAlgorithm('Unsupported key type!', key=key)
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
    raise UnsupportedAlgorithm(
        'Unsupported algorithm: %s' % algorithm, algorithm_id=algorithm)


def _pkcs1_15_pad(algorithm, message):
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(message)
    t = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05' + \
        b'\x00\x04\x20' + h.finalize()
    em_len = 128 if algorithm == ALGO.RSA1024 else 256
    f_len = em_len - len(t) - 3
    return b'\0\1' + b'\xff' * f_len + b'\0' + t


_sign_len_conditions = {
    ALGO.RSA1024: lambda ln: ln == 128,
    ALGO.RSA2048: lambda ln: ln == 256,
    ALGO.ECCP256: lambda ln: ln <= 32,
    ALGO.ECCP384: lambda ln: ln <= 48
}


_decrypt_len_conditions = {
    ALGO.RSA1024: lambda ln: ln == 128,
    ALGO.RSA2048: lambda ln: ln == 256,
    ALGO.ECCP256: lambda ln: ln == 65,
    ALGO.ECCP384: lambda ln: ln == 97
}


def _derive_key(pin, salt):
    kdf = PBKDF2HMAC(hashes.SHA1(), 24, salt, 10000, default_backend())
    return kdf.derive(pin.encode('utf-8'))


def generate_random_management_key():
    return os.urandom(24)


def is_verify_fail(sw, applet_version):
    if applet_version < (1, 0, 4):
        return 0x6300 <= sw <= 0x63ff
    else:
        return SW.is_verify_fail(sw)


def tries_left(sw, applet_version):
    if applet_version < (1, 0, 4):
        if sw == SW.AUTH_METHOD_BLOCKED:
            return 0

        if not is_verify_fail(sw, applet_version):
            raise ValueError(
                'Cannot read remaining tries from status word: %x' % sw)

        return sw & 0xff
    else:
        return SW.tries_left(sw)


class PivmanData(object):

    def __init__(self, raw_data=Tlv(0x80)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
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

    @property
    def mgm_key_protected(self):
        return self._get_flag(0x02)

    @mgm_key_protected.setter
    def mgm_key_protected(self, value):
        self._set_flag(0x02, value)

    def get_bytes(self):
        data = b''
        if self._flags is not None:
            data += Tlv(0x81, struct.pack('>B', self._flags))
        if self.salt is not None:
            data += Tlv(0x82, self.salt)
        if self.pin_timestamp is not None:
            data += Tlv(0x83, struct.pack('>I', self.pin_timestamp))
        return Tlv(0x80, data)


class PivmanProtectedData(object):

    def __init__(self, raw_data=Tlv(0x88)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self.key = data.get(0x89)

    def get_bytes(self):
        data = b''
        if self.key is not None:
            data += Tlv(0x89, self.key)
        return Tlv(0x88, data)


class PivController(object):

    def __init__(self, driver):
        driver.select(AID.PIV)
        self._authenticated = False
        self._driver = driver
        self._version = self._read_version()
        self._update_pivman_data()

    def _update_pivman_data(self):
        try:
            self._pivman_data = PivmanData(self.get_data(OBJ.PIVMAN_DATA))
        except APDUError:
            self._pivman_data = PivmanData()

    @property
    def version(self):
        return self._version

    @property
    def has_protected_key(self):
        return self.has_derived_key or self.has_stored_key

    @property
    def has_derived_key(self):
        return self._pivman_data.salt is not None

    @property
    def has_stored_key(self):
        return self._pivman_data.mgm_key_protected

    @property
    def puk_blocked(self):
        return self._pivman_data.puk_blocked

    def send_cmd(self, ins, p1=0, p2=0, data=b'', check=SW.OK):
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

    def _init_pivman_protected(self):
        try:
            self._pivman_protected_data = PivmanProtectedData(
                self.get_data(OBJ.PIVMAN_PROTECTED_DATA))
        except APDUError as e:
            if e.sw == SW.NOT_FOUND:
                # No data there, initialise a new object.
                self._pivman_protected_data = PivmanProtectedData()
            else:
                raise

    def verify(self, pin, touch_callback=None):
        try:
            self.send_cmd(INS.VERIFY, 0, PIN, _pack_pin(pin))
        except APDUError as e:
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise AuthenticationBlocked('PIN is blocked.', e.sw)

            elif is_verify_fail(e.sw, self.version):
                raise WrongPin(e.sw, self.version)

            raise

        if self.has_derived_key and not self._authenticated:
            self.authenticate(
                _derive_key(pin, self._pivman_data.salt), touch_callback)
            self.verify(pin, touch_callback)

        if self.has_stored_key and not self._authenticated:
            self._init_pivman_protected()
            self.authenticate(self._pivman_protected_data.key, touch_callback)
            self.verify(pin, touch_callback)

    def change_pin(self, old_pin, new_pin):
        try:
            self.send_cmd(INS.CHANGE_REFERENCE, 0, PIN,
                          _pack_pin(old_pin) + _pack_pin(new_pin))
        except APDUError as e:
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise AuthenticationBlocked('PIN is blocked.', e.sw)

            elif is_verify_fail(e.sw, self.version):
                raise WrongPin(e.sw, self.version)

            raise

        if self.has_derived_key:
            if not self._authenticated:
                self.authenticate(_derive_key(old_pin, self._pivman_data.salt))
            self.use_derived_key(new_pin)

    def change_puk(self, old_puk, new_puk):
        try:
            self.send_cmd(INS.CHANGE_REFERENCE, 0, PUK,
                          _pack_pin(old_puk) + _pack_pin(new_puk))
        except APDUError as e:
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise AuthenticationBlocked('PUK is blocked.', e.sw)

            elif is_verify_fail(e.sw, self.version):
                raise WrongPuk(e.sw, self.version)

            raise

    def unblock_pin(self, puk, new_pin):
        try:
            self.send_cmd(
                INS.RESET_RETRY, 0, PIN, _pack_pin(puk) + _pack_pin(new_pin))
        except APDUError as e:
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise AuthenticationBlocked('PUK is blocked.', e.sw)

            elif is_verify_fail(e.sw, self.version):
                raise WrongPuk(e.sw, self.version)

            raise

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
        try:
            cipher_key = algorithms.TripleDES(key)
        except ValueError:
            raise BadFormat('Management key must be exactly 24 bytes long, '
                            'was: {}'.format(len(key)), None)
        cipher = Cipher(cipher_key, modes.ECB(), backend)
        decryptor = cipher.decryptor()
        pt1 = decryptor.update(ct1) + decryptor.finalize()
        ct2 = os.urandom(8)

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        try:
            pt2 = self.send_cmd(
                INS.AUTHENTICATE, ALGO.TDES, SLOT.CARD_MANAGEMENT,
                Tlv(TAG.DYN_AUTH, Tlv(0x80, pt1) + Tlv(0x81, ct2))
                )[4:12]

        except APDUError as e:
            if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                raise AuthenticationFailed(
                    'Incorrect management key', e.sw, self.version)

            logger.error('Failed to authenticate management key.', exc_info=e)
            raise

        except Exception as e:
            logger.error('Failed to authenticate management key.', exc_info=e)
            raise

        finally:
            if touch_callback is not None:
                touch_timer.cancel()

        encryptor = cipher.encryptor()
        pt2_cmp = encryptor.update(ct2) + encryptor.finalize()
        if not bytes_eq(pt2, pt2_cmp):
            raise ValueError('Device challenge did not match!')
        self._authenticated = True

    def set_mgm_key(self, new_key, touch=False, store_on_device=False):
        # If the key should be protected by PIN and no key is given,
        # we generate a random key.
        if not new_key:
            if store_on_device:
                new_key = generate_random_management_key()
            else:
                raise ValueError('new_key was not given and '
                                 'store_on_device was not True')

        if len(new_key) != 24:
            raise BadFormat(
                'Management key must be exactly 24 bytes long, was: {}'.format(
                    len(new_key)),
                new_key)

        if store_on_device or (not store_on_device and self.has_stored_key):
            # Ensure we have access to protected data before overwriting key
            try:
                self._init_pivman_protected()
            except Exception as e:
                logger.debug('Failed to initialize protected pivman data',
                             exc_info=e)

                if store_on_device:
                    raise

        # Set the new management key
        self.send_cmd(
            INS.SET_MGMKEY, 0xff, 0xfe if touch else 0xff,
            six.int2byte(ALGO.TDES) + Tlv(SLOT.CARD_MANAGEMENT, new_key))
        if self.has_derived_key:
            # Clear salt for old derived keys.
            self._pivman_data.salt = None
        # Set flag for stored or not stored key.
        self._pivman_data.mgm_key_protected = store_on_device
        # Update readable pivman data
        self.put_data(OBJ.PIVMAN_DATA, self._pivman_data.get_bytes())
        if store_on_device:
            # Store key in protected pivman data
            self._pivman_protected_data.key = new_key
            self.put_data(
                OBJ.PIVMAN_PROTECTED_DATA,
                self._pivman_protected_data.get_bytes())
        elif not store_on_device and self.has_stored_key:
            # If new key should not be stored and there is an old stored key,
            # try to clear it.
            try:
                self._pivman_protected_data.key = None
                self.put_data(
                    OBJ.PIVMAN_PROTECTED_DATA,
                    self._pivman_protected_data.get_bytes())
            except APDUError as e:
                logger.debug("No PIN provided, can't clear key..", exc_info=e)
        # Update CHUID and CCC if not set
        try:
            self.get_data(OBJ.CAPABILITY)
        except APDUError as e:
            if e.sw == SW.NOT_FOUND:
                self.update_ccc()
            else:
                logger.debug('Failed to read CCC...', exc_info=e)
        try:
            self.get_data(OBJ.CHUID)
        except APDUError as e:
            if e.sw == SW.NOT_FOUND:
                self.update_chuid()
            else:
                logger.debug('Failed to read CHUID...', exc_info=e)

    def get_pin_tries(self):
        """
        Returns the number of PIN retries left,
        0 PIN authentication blocked. Note that 15 is the highest
        value that will be returned even if remaining tries is higher.
        """
        # Verify without PIN gives number of tries left.
        _, sw = self.send_cmd(INS.VERIFY, 0, PIN, check=None)
        return tries_left(sw, self.version)

    def _get_puk_tries(self):
        # A failed unblock pin will return number of PUK tries left,
        # but also uses one try.
        _, sw = self.send_cmd(INS.RESET_RETRY, 0, PIN, _pack_pin('')*2,
                              check=None)
        return tries_left(sw, self.version)

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
        self._update_pivman_data()

    def get_data(self, object_id):
        id_bytes = struct.pack(b'>I', object_id).lstrip(b'\0')
        tlv = Tlv(self.send_cmd(INS.GET_DATA, 0x3f, 0xff,
                                Tlv(TAG.OBJ_ID, id_bytes)))
        if tlv.tag not in [TAG.OBJ_DATA, OBJ.DISCOVERY]:
            raise ValueError('Wrong tag in response data!')
        return tlv.value

    def put_data(self, object_id, data):
        id_bytes = struct.pack(b'>I', object_id).lstrip(b'\0')
        self.send_cmd(INS.PUT_DATA, 0x3f, 0xff, Tlv(TAG.OBJ_ID, id_bytes) +
                      Tlv(TAG.OBJ_DATA, data))

    def generate_key(self, slot, algorithm, pin_policy=PIN_POLICY.DEFAULT,
                     touch_policy=TOUCH_POLICY.DEFAULT):

        if ALGO.is_rsa(algorithm):
            ensure_not_cve201715361_vulnerable_firmware_version(self.version)

        if algorithm not in self.supported_algorithms:
            raise UnsupportedAlgorithm(
                'Algorithm not supported on this YubiKey: {}'
                .format(algorithm),
                algorithm_id=algorithm)

        data = Tlv(TAG.ALGO, six.int2byte(algorithm))
        if pin_policy:
            data += Tlv(TAG.PIN_POLICY, six.int2byte(pin_policy))
        if touch_policy:
            data += Tlv(TAG.TOUCH_POLICY, six.int2byte(touch_policy))
        data = Tlv(0xac, data)
        resp = self.send_cmd(INS.GENERATE_ASYMMETRIC, 0, slot, data)
        key_data = Tlv.parse_dict(Tlv.unpack(0x7f49, resp))
        if algorithm in [ALGO.RSA1024, ALGO.RSA2048]:
            return rsa.RSAPublicNumbers(
                int_from_bytes(key_data[0x82], 'big'),
                int_from_bytes(key_data[0x81], 'big')
            ).public_key(default_backend())
        elif algorithm in [ALGO.ECCP256, ALGO.ECCP384]:
            curve = ec.SECP256R1 if algorithm == ALGO.ECCP256 else ec.SECP384R1

            try:
                # Added in cryptography 2.5
                return ec.EllipticCurvePublicKey.from_encoded_point(
                    curve(),
                    key_data[0x86]
                )
            except AttributeError:
                return ec.EllipticCurvePublicNumbers.from_encoded_point(
                    curve(),
                    key_data[0x86]
                ).public_key(default_backend())

        raise UnsupportedAlgorithm(
            'Invalid algorithm: {}'.format(algorithm),
            algorithm_id=algorithm)

    def generate_self_signed_certificate(
            self, slot, public_key, common_name, valid_from, valid_to,
            touch_callback=None):

        algorithm = ALGO.from_public_key(public_key)

        builder = x509.CertificateBuilder()
        builder = builder.public_key(public_key)
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name), ]))

        # Same as subject on self-signed certificates.
        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name), ]))

        # x509.random_serial_number added in cryptography 1.6
        serial = int_from_bytes(os.urandom(20), 'big') >> 1
        builder = builder.serial_number(serial)

        builder = builder.not_valid_before(valid_from)
        builder = builder.not_valid_after(valid_to)

        try:
            cert = self.sign_cert_builder(
                slot, algorithm, builder, touch_callback)
        except APDUError as e:
            logger.error('Failed to generate certificate for slot %s', slot,
                         exc_info=e)
            raise

        self.import_certificate(slot, cert, verify=False)

    def generate_certificate_signing_request(self, slot, public_key, subject,
                                             touch_callback=None):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject), ]))

        try:
            return self.sign_csr_builder(
                slot, public_key, builder, touch_callback=touch_callback)
        except APDUError as e:
            logger.error(
                'Failed to generate Certificate Signing Request for slot %s',
                slot, exc_info=e)
            raise

    def import_key(self, slot, key, pin_policy=PIN_POLICY.DEFAULT,
                   touch_policy=TOUCH_POLICY.DEFAULT):
        algorithm, data = _get_key_data(key)
        if pin_policy:
            data += Tlv(TAG.PIN_POLICY, six.int2byte(pin_policy))
        if touch_policy:
            data += Tlv(TAG.TOUCH_POLICY, six.int2byte(touch_policy))
        self.send_cmd(INS.IMPORT_KEY, algorithm, slot, data)
        return algorithm

    def import_certificate(
            self, slot, certificate, verify=False, touch_callback=None):
        cert_data = certificate.public_bytes(Encoding.DER)

        if verify:
            # Verify that the public key used in the certificate
            # is from the same keypair as the private key.
            try:
                public_key = certificate.public_key()

                test_data = b'test'

                if touch_callback is not None:
                    touch_timer = Timer(0.500, touch_callback)
                    touch_timer.start()

                test_sig = self.sign(
                    slot, ALGO.from_public_key(public_key), test_data)

                if touch_callback is not None:
                    touch_timer.cancel()

                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        test_sig, test_data, padding.PKCS1v15(),
                        certificate.signature_hash_algorithm)
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        test_sig, test_data, ec.ECDSA(hashes.SHA256()))
                else:
                    raise ValueError('Unknown key type: ' + type(public_key))

            except APDUError as e:
                if e.sw == SW.INCORRECT_PARAMETERS:
                    raise KeypairMismatch(slot, certificate)
                raise

            except InvalidSignature:
                raise KeypairMismatch(slot, certificate)

        self.put_data(OBJ.from_slot(slot), Tlv(TAG.CERTIFICATE, cert_data) +
                      Tlv(TAG.CERT_INFO, b'\0') + Tlv(TAG.LRC))
        self.update_chuid()

    def read_certificate(self, slot):
        data = Tlv.parse_dict(self.get_data(OBJ.from_slot(slot)))
        if TAG.CERT_INFO in data:  # Not available in attestation slot
            if data[TAG.CERT_INFO] != b'\0':
                raise ValueError('Compressed certificates are not supported!')
        try:
            return x509.load_der_x509_certificate(data[TAG.CERTIFICATE],
                                                  default_backend())
        except Exception:
            raise InvalidCertificate(slot)

    def delete_certificate(self, slot):
        self.put_data(OBJ.from_slot(slot), b'')

    def attest(self, slot):
        return x509.load_der_x509_certificate(self.send_cmd(INS.ATTEST, slot),
                                              default_backend())

    def _raw_sign_decrypt(self, slot, algorithm, payload, condition):
        if not condition(len(payload.value)):
            raise BadFormat(
                'Input has invalid length for algorithm %s' % algorithm,
                len(payload.value))

        data = Tlv(TAG.DYN_AUTH, Tlv(0x82) + payload)
        resp = self.send_cmd(INS.AUTHENTICATE, algorithm, slot, data)
        return Tlv.unpack(0x82, Tlv.unpack(0x7c, resp))

    def sign_raw(self, slot, algorithm, message):
        return self._raw_sign_decrypt(slot, algorithm, Tlv(0x81, message),
                                      _sign_len_conditions[algorithm])

    def sign(self, slot, algorithm, message):
        if algorithm in (ALGO.RSA1024, ALGO.RSA2048):
            message = _pkcs1_15_pad(algorithm, message)
        elif algorithm in (ALGO.ECCP256, ALGO.ECCP384):
            h = hashes.Hash(hashes.SHA256(), default_backend())
            h.update(message)
            message = h.finalize()
        return self.sign_raw(slot, algorithm, message)

    def decrypt_raw(self, slot, algorithm, message):
        return self._raw_sign_decrypt(slot, algorithm, Tlv(0x85, message),
                                      _decrypt_len_conditions[algorithm])

    def list_certificates(self):
        certs = OrderedDict()
        for slot in set(SLOT) - {SLOT.CARD_MANAGEMENT, SLOT.ATTESTATION}:
            try:
                certs[slot] = self.read_certificate(slot)
            except APDUError:
                pass
            except InvalidCertificate:
                certs[slot] = None

        return certs

    def update_chuid(self):
        # Non-Federal Issuer FASC-N
        # [9999-9999-999999-0-1-0000000000300001]
        FASC_N = b'\xd4\xe7\x39\xda\x73\x9c\xed\x39\xce\x73\x9d\x83\x68' + \
                 b'\x58\x21\x08\x42\x10\x84\x21\xc8\x42\x10\xc3\xeb'
        # Expires on: 2030-01-01
        EXPIRY = b'\x32\x30\x33\x30\x30\x31\x30\x31'

        self.put_data(
            OBJ.CHUID,
            Tlv(0x30, FASC_N) +
            Tlv(0x34, os.urandom(16)) +
            Tlv(0x35, EXPIRY) +
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

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        sig = self.sign(slot, algorithm, cert.tbs_certificate_bytes)

        if touch_callback is not None:
            touch_timer.cancel()

        seq = Tlv.parse_list(Tlv.unpack(0x30, cert.public_bytes(Encoding.DER)))
        # Replace signature, add unused bits = 0
        seq[2] = Tlv(seq[2].tag, b'\0' + sig)
        # Re-assemble sequence
        der = Tlv(0x30, b''.join(seq))

        return x509.load_der_x509_certificate(der, default_backend())

    def sign_csr_builder(self, slot, public_key, builder, touch_callback=None):
        algorithm = ALGO.from_public_key(public_key)
        dummy_key = _dummy_key(algorithm)
        csr = builder.sign(dummy_key, hashes.SHA256(), default_backend())
        seq = Tlv.parse_list(Tlv.unpack(0x30, csr.public_bytes(Encoding.DER)))

        # Replace public key
        pub_format = PublicFormat.PKCS1 if algorithm.name.startswith('RSA') \
            else PublicFormat.SubjectPublicKeyInfo
        dummy_bytes = dummy_key.public_key().public_bytes(
            Encoding.DER, pub_format)
        pub_bytes = public_key.public_bytes(Encoding.DER, pub_format)
        seq[0] = seq[0].replace(dummy_bytes, pub_bytes)

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        sig = self.sign(slot, algorithm, seq[0])

        if touch_callback is not None:
            touch_timer.cancel()

        # Replace signature, add unused bits = 0
        seq[2] = Tlv(seq[2].tag, b'\0' + sig)
        # Re-assemble sequence
        der = Tlv(0x30, b''.join(seq))

        return x509.load_der_x509_csr(der, default_backend())

    @property
    def supports_pin_policies(self):
        return self.version >= (4, 0, 0)

    @property
    def supported_touch_policies(self):
        if self.version < (4, 0, 0):
            return []  # Touch policy not supported on NEO.
        elif self.version < (4, 3, 0):
            return [TOUCH_POLICY.DEFAULT, TOUCH_POLICY.NEVER,
                    TOUCH_POLICY.ALWAYS]  # Cached policy was added in 4.3
        else:
            return [policy for policy in TOUCH_POLICY]

    @property
    def supported_algorithms(self):
        return [
            alg for alg in ALGO

            if not alg == ALGO.TDES
            if not (ALGO.is_rsa(alg) and
                    is_cve201715361_vulnerable_firmware_version(self.version))
            if not (alg == ALGO.ECCP384 and self.version < (4, 0, 0))
            if not (alg == ALGO.RSA1024 and
                    YubiKey.is_fips_version(self.version))
        ]
