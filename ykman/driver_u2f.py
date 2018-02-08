# Copyright (c) 2015 Yubico AB
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

from . import cbor
from .native.u2fh import U2fh, u2fh_devs
from .driver import AbstractDriver, ModeSwitchError
from .util import TRANSPORT, YUBIKEY, PID, MissingLibrary, parse_tlvs
from enum import IntEnum, unique
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ctypes import POINTER, byref, c_uint, c_size_t, create_string_buffer
from binascii import b2a_hex, a2b_hex
import logging
import weakref
import struct
import six


logger = logging.getLogger(__name__)

U2F_VENDOR_FIRST = 0x40
TYPE_INIT = 0x80
IV = b'\x00' * 16


@unique
class CTAPHID(IntEnum):
    MSG = TYPE_INIT | 0x03
    CBOR = TYPE_INIT | 0x10
    PING = TYPE_INIT | 0x01
    YUBIKEY_DEVICE_CONFIG = TYPE_INIT | U2F_VENDOR_FIRST
    YK4_CAPABILITIES = TYPE_INIT | U2F_VENDOR_FIRST + 2


try:
    u2fh = U2fh('u2f-host', '0')

    # TODO: Allow debug output
    if u2fh.u2fh_global_init(0) is not 0:
        raise Exception('u2fh_global_init failed!')
    libversion = tuple(int(x) for x in u2fh.u2fh_check_version(None)
                       .decode('ascii').split('.'))
except Exception as e:
    logger.error('libu2f-host not found', exc_info=e)
    u2fh = MissingLibrary(
        'libu2f-host not found, U2F connectability not available!')
    libversion = None


class U2FHostError(Exception):
    """Thrown if u2f-host call fails."""

    def __init__(self, errno):
        self.errno = errno
        self.message = '{}: {}'.format(u2fh.u2fh_strerror_name(errno),
                                       u2fh.u2fh_strerror(errno))

    def __str__(self):
        return 'u2fh error {}, {}'.format(self.errno, self.message)


def check(status):
    if status is not 0:
        raise U2FHostError(status)


def _pid_from_name(name):
    if 'Security Key' in name:
        return PID.SKY_U2F

    if 'Plus' in name:
        return PID.YKP_OTP_U2F

    transports = 0
    for t in TRANSPORT:
        if t.name in name:
            transports += t

    key_type = YUBIKEY.NEO if 'NEO' in name else YUBIKEY.YK4
    return key_type.get_pid(transports)


_instances = weakref.WeakSet()


class U2FDriver(AbstractDriver):
    """
    libu2f-host based U2F driver
    """
    transport = TRANSPORT.U2F

    def __init__(self, devs, index, name):
        self._devs = devs
        self._index = index
        self._pid = _pid_from_name(name)
        _instances.add(self)

        self._version = [0, 0, 0]
        self._capa = b''
        if self.key_type == YUBIKEY.YK4:
            self._version[0] = 4
            try:
                self._capa = self.sendrecv(CTAPHID.YK4_CAPABILITIES, b'\x00')
                data = self._capa
                c_len, data = six.indexbytes(data, 0), data[1:]
                data = data[:c_len]
                for tlv in parse_tlvs(data):
                    if tlv.tag == 0x02:
                        self._serial = int(b2a_hex(tlv.value), 16)
                self._version[1] = 2
            except U2FHostError:  # Pre 4.2
                self._version[1] = 1
        elif self.key_type == YUBIKEY.NEO:
            self._version = [3, 2, 0]
        elif self.key_type == YUBIKEY.YKP:
            self._version = [4, 0, 0]

        try:
            self.fido2 = Fido2Client(self)
        except U2FHostError:
            self.fido2 = None

    def read_capabilities(self):
        return self._capa

    def guess_version(self):
        return tuple(self._version), False

    def sendrecv(self, cmd, data):
        buf_size = c_size_t(1024)
        resp = create_string_buffer(buf_size.value)
        check(u2fh.u2fh_sendrecv(self._devs, self._index, cmd, data,
                                 len(data), resp, byref(buf_size)))
        return resp.raw[0:buf_size.value]

    def set_mode(self, mode_code, cr_timeout=0, autoeject_time=0):
        data = struct.pack('BBH', mode_code, cr_timeout, autoeject_time)
        try:
            self.sendrecv(CTAPHID.YUBIKEY_DEVICE_CONFIG, data)
        except U2FHostError:
            raise ModeSwitchError()

    def __del__(self):
        if not _instances.difference({self}):
            u2fh.u2fh_devs_done(self._devs)


class CTAP2Error(Exception):
    def __init__(self, code):
        self.code = code
        self.message = 'Error code: 0x%02x' % code

    def __str__(self):
        return self.message


@unique
class CTAP2_CMD(IntEnum):
    GET_INFO = 0x04
    CLIENT_PIN = 0x06
    RESET = 0x07


@unique
class CTAP2_PIN_ARG(IntEnum):
    PIN_PROTOCOL = 0x01
    COMMAND = 0x02
    KEY_AGREEMENT = 0x03
    PIN_AUTH = 0x04
    NEW_PIN_ENC = 0x05
    PIN_HASH_ENC = 0x06
    GET_KEY_AGREEMENT = 0x07
    GET_RETRIES = 0x08


@unique
class CTAP2_PIN_RES(IntEnum):
    KEY_AGREEMENT = 0x01
    PIN_TOKEN = 0x02
    RETRIES = 0x03


def _pad_pin(pin):
    if not isinstance(pin, six.text_type):
        raise ValueError('PIN of wrong type, expecting %s' % six.text_type)
    if len(pin) < 4:
        raise ValueError('PIN must be >= 4 characters')
    pin = pin.encode('utf8').ljust(64, b'\0')
    pin += b'\0' * (-(len(pin) - 16) % 16)
    if len(pin) > 255:
        raise ValueError('PIN must be <= 255 bytes')
    return pin


class Fido2Client(object):

    def __init__(self, driver):
        self._driver = driver
        self._info = self._get_info()
        self._pin = self._info[4]['clientPin']
        self._key_agreement = None
        self._shared = None

    def send_cbor_cmd(self, cmd, data=None):
        request = struct.pack('>B', cmd)
        if data is not None:
            request += cbor.serialize(data)
        data = self._driver.sendrecv(CTAPHID.CBOR, request)
        status = six.indexbytes(data, 0)
        if status != 0x00:
            raise CTAP2Error(status)
        if len(data) == 1:
            return None
        response, rest = cbor.deserialize(data[1:])
        if rest != b'':
            raise ValueError('Invalid response')
        return response

    @property
    def has_pin(self):
        return self._pin

    def _get_info(self):
        return self.send_cbor_cmd(CTAP2_CMD.GET_INFO)

    def _init_shared_secret(self):
        resp = self._auth_client_pin(2, {
            CTAP2_PIN_ARG.GET_KEY_AGREEMENT: True
        })
        be = default_backend()
        sk = ec.generate_private_key(ec.SECP256R1(), be)
        pk = sk.public_key().public_numbers()
        self._key_agreement = {
            1: 2,
            3: -15,
            -1: 1,
            -2: a2b_hex('%064x' % pk.x),
            -3: a2b_hex('%064x' % pk.y)
        }
        pk = resp[CTAP2_PIN_RES.KEY_AGREEMENT]
        x = int(b2a_hex(pk[-2]), 16)
        y = int(b2a_hex(pk[-3]), 16)
        pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
        h = hashes.Hash(hashes.SHA256(), be)
        h.update(sk.exchange(ec.ECDH(), pk))
        self._shared = h.finalize()

    def _ensure_shared(self):
        if self._shared is None:
            self._init_shared_secret()

    def _auth_client_pin(self, cmd, args):
        args.update({
            CTAP2_PIN_ARG.PIN_PROTOCOL: 1,
            CTAP2_PIN_ARG.COMMAND: cmd
        })
        return self.send_cbor_cmd(CTAP2_CMD.CLIENT_PIN, args)

    def _get_pin_token(self, pin):
        self._ensure_shared()
        be = default_backend()
        cipher = Cipher(algorithms.AES(self._shared), modes.CBC(IV), be)
        h = hashes.Hash(hashes.SHA256(), default_backend())
        h.update(pin.encode('utf8'))
        pin_hash = h.finalize()[:16]
        enc = cipher.encryptor()
        pin_hash_enc = enc.update(pin_hash) + enc.finalize()

        try:
            resp = self._auth_client_pin(5, {
                CTAP2_PIN_ARG.KEY_AGREEMENT: self._key_agreement,
                CTAP2_PIN_ARG.PIN_HASH_ENC: pin_hash_enc
            })
            dec = cipher.decryptor()
            return dec.update(resp[CTAP2_PIN_RES.PIN_TOKEN]) + dec.finalize()
        except ValueError:
            self._shared = None
            self._key_agreement = None
            raise

    def get_pin_retries(self):
        resp = self._auth_client_pin(1, {
            CTAP2_PIN_ARG.GET_RETRIES: True
        })
        return resp[CTAP2_PIN_RES.RETRIES]

    def set_pin(self, pin):
        pin = _pad_pin(pin)

        self._ensure_shared()
        be = default_backend()
        cipher = Cipher(algorithms.AES(self._shared), modes.CBC(IV), be)
        enc = cipher.encryptor()
        pin_enc = enc.update(pin) + enc.finalize()
        h = hmac.HMAC(self._shared, hashes.SHA256(), be)
        h.update(pin_enc)
        pin_auth = h.finalize()[:16]
        self._auth_client_pin(3, {
            CTAP2_PIN_ARG.KEY_AGREEMENT: self._key_agreement,
            CTAP2_PIN_ARG.NEW_PIN_ENC: pin_enc,
            CTAP2_PIN_ARG.PIN_AUTH: pin_auth
        })
        self._pin = True

    def change_pin(self, old_pin, new_pin):
        new_pin = _pad_pin(new_pin)

        self._ensure_shared()
        be = default_backend()
        cipher = Cipher(algorithms.AES(self._shared), modes.CBC(IV), be)
        h = hashes.Hash(hashes.SHA256(), default_backend())
        h.update(old_pin.encode('utf8'))
        pin_hash = h.finalize()[:16]
        enc = cipher.encryptor()
        pin_hash_enc = enc.update(pin_hash) + enc.finalize()
        enc = cipher.encryptor()
        pin_enc = enc.update(new_pin) + enc.finalize()
        h = hmac.HMAC(self._shared, hashes.SHA256(), be)
        h.update(pin_enc)
        h.update(pin_hash_enc)
        pin_auth = h.finalize()[:16]
        self._auth_client_pin(4, {
            CTAP2_PIN_ARG.KEY_AGREEMENT: self._key_agreement,
            CTAP2_PIN_ARG.PIN_HASH_ENC: pin_hash_enc,
            CTAP2_PIN_ARG.NEW_PIN_ENC: pin_enc,
            CTAP2_PIN_ARG.PIN_AUTH: pin_auth
        })

    def reset(self):
        self.send_cbor_cmd(CTAP2_CMD.RESET)
        self._pin = False


def open_devices():
    devs = POINTER(u2fh_devs)()
    check(u2fh.u2fh_devs_init(byref(devs)))
    max_index = c_uint()
    u2fh.u2fh_devs_discover(devs, byref(max_index))
    resp = create_string_buffer(1024)
    for index in range(max_index.value + 1):
        buf_size = c_size_t(1024)
        if u2fh.u2fh_get_device_description(
                devs, index, resp, byref(buf_size)) == 0:
            name = resp.value.decode('utf8')
            if name.startswith('Yubikey') \
                    or name.startswith('Security Key by Yubico'):
                yield U2FDriver(devs, index, name)
