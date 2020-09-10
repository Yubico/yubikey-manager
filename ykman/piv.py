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

from yubikit.core import Tlv, BadResponseError
from yubikit.core.iso7816 import ApduError, SW
from yubikit.piv import (
    SLOT,
    OBJECT_ID,
    KEY_TYPE,
    ALGORITHM,
    PIN_POLICY,
    TOUCH_POLICY,
    TAG_LRC,
)

from .device import is_fips_version
from .util import (
    is_cve201715361_vulnerable_firmware_version,
    ensure_not_cve201715361_vulnerable_firmware_version,
)
from cryptography import x509
from cryptography.utils import int_from_bytes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from collections import OrderedDict
from threading import Timer
import logging
import struct
import os


logger = logging.getLogger(__name__)


OBJECT_ID_PIVMAN_DATA = 0x5FFF00
OBJECT_ID_PIVMAN_PROTECTED_DATA = OBJECT_ID.PRINTED  # Use slot for printed information.


class BadFormat(Exception):
    def __init__(self, message, bad_value):
        super(BadFormat, self).__init__(message)
        self.bad_value = bad_value


class InvalidCertificate(Exception):
    def __init__(self, slot):
        super(InvalidCertificate, self).__init__(
            "Failed to parse certificate in slot {:x}".format(slot)
        )
        self.slot = slot


class KeypairMismatch(Exception):
    def __init__(self, slot, cert):
        super(KeypairMismatch, self).__init__(
            "The certificate does not match the private key in slot %s." % slot
        )
        self.slot = slot
        self.cert = cert


class UnsupportedAlgorithm(Exception):
    def __init__(
        self, message, algorithm_id=None, key=None,
    ):
        super(UnsupportedAlgorithm, self).__init__(message)
        if algorithm_id is None and key is None:
            raise ValueError("At least one of algorithm_id and key must be given.")

        self.algorithm_id = algorithm_id
        self.key = key


def _dummy_key(algorithm):
    if algorithm == KEY_TYPE.RSA1024:
        return rsa.generate_private_key(65537, 1024, default_backend())  # nosec
    if algorithm == KEY_TYPE.RSA2048:
        return rsa.generate_private_key(65537, 2048, default_backend())
    if algorithm == KEY_TYPE.ECCP256:
        return ec.generate_private_key(ec.SECP256R1(), default_backend())
    if algorithm == KEY_TYPE.ECCP384:
        return ec.generate_private_key(ec.SECP384R1(), default_backend())
    raise UnsupportedAlgorithm(
        "Unsupported algorithm: %s" % algorithm, algorithm_id=algorithm
    )


def _derive_key(pin, salt):
    kdf = PBKDF2HMAC(hashes.SHA1(), 24, salt, 10000, default_backend())  # nosec
    return kdf.derive(pin.encode("utf-8"))


def generate_random_management_key():
    return os.urandom(24)


class PivmanData(object):
    def __init__(self, raw_data=Tlv(0x80)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self._flags = struct.unpack(">B", data[0x81])[0] if 0x81 in data else None
        self.salt = data.get(0x82)
        self.pin_timestamp = struct.unpack(">I", data[0x83]) if 0x83 in data else None

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
        data = b""
        if self._flags is not None:
            data += Tlv(0x81, struct.pack(">B", self._flags))
        if self.salt is not None:
            data += Tlv(0x82, self.salt)
        if self.pin_timestamp is not None:
            data += Tlv(0x83, struct.pack(">I", self.pin_timestamp))
        return Tlv(0x80, data)


class PivmanProtectedData(object):
    def __init__(self, raw_data=Tlv(0x88)):
        data = Tlv.parse_dict(Tlv(raw_data).value)
        self.key = data.get(0x89)

    def get_bytes(self):
        data = b""
        if self.key is not None:
            data += Tlv(0x89, self.key)
        return Tlv(0x88, data)


class PivController(object):
    def __init__(self, app):
        self._app = app
        self._authenticated = False
        self._update_pivman_data()

    def _update_pivman_data(self):
        try:
            self._pivman_data = PivmanData(self.get_data(OBJECT_ID_PIVMAN_DATA))
        except ApduError:
            self._pivman_data = PivmanData()

    @property
    def version(self):
        return self._app.version

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

    def _init_pivman_protected(self):
        try:
            self._pivman_protected_data = PivmanProtectedData(
                self.get_data(OBJECT_ID_PIVMAN_PROTECTED_DATA)
            )
        except ApduError as e:
            if e.sw == SW.FILE_NOT_FOUND:
                # No data there, initialise a new object.
                self._pivman_protected_data = PivmanProtectedData()
            else:
                raise

    def verify(self, pin, touch_callback=None):
        self._app.verify_pin(pin)

        if not self._authenticated:
            if self.has_derived_key:
                self.authenticate(
                    _derive_key(pin, self._pivman_data.salt), touch_callback
                )
                self.verify(pin, touch_callback)
            elif self.has_stored_key:
                self._init_pivman_protected()
                self.authenticate(self._pivman_protected_data.key, touch_callback)
                self.verify(pin, touch_callback)

    def change_pin(self, old_pin, new_pin):
        self._app.change_pin(old_pin, new_pin)

        if self.has_derived_key:
            if not self._authenticated:
                self.authenticate(_derive_key(old_pin, self._pivman_data.salt))
            self._use_derived_key(new_pin)

    def change_puk(self, old_puk, new_puk):
        self._app.change_puk(old_puk, new_puk)

    def unblock_pin(self, puk, new_pin):
        self._app.unblock_pin(puk, new_pin)

    def set_pin_retries(self, pin_retries, puk_retries):
        self._app.set_pin_attempts(pin_retries, puk_retries)

    def _use_derived_key(self, pin, touch=False):
        self.verify(pin)
        new_salt = os.urandom(16)
        new_key = _derive_key(pin, new_salt)
        self._app.set_management_key(new_key)
        self._pivman_data.salt = new_salt
        self._app.put_data(OBJECT_ID_PIVMAN_DATA, self._pivman_data.get_bytes())

    def set_pin_timestamp(self, timestamp):
        self._pivman_data.pin_timestamp = timestamp
        self._app.put_data(OBJECT_ID_PIVMAN_DATA, self._pivman_data.get_bytes())

    def authenticate(self, key, touch_callback=None):
        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        try:
            self._app.authenticate(key)
        except Exception as e:
            logger.error("Failed to authenticate management key.", exc_info=e)
            raise
        finally:
            if touch_callback is not None:
                touch_timer.cancel()

        self._authenticated = True

    def set_mgm_key(self, new_key, touch=False, store_on_device=False):
        # If the key should be protected by PIN and no key is given,
        # we generate a random key.
        if not new_key:
            if store_on_device:
                new_key = generate_random_management_key()
            else:
                raise ValueError(
                    "new_key was not given and store_on_device was not True"
                )

        if len(new_key) != 24:
            raise BadFormat(
                "Management key must be exactly 24 bytes long, was: {}".format(
                    len(new_key)
                ),
                new_key,
            )

        if store_on_device or (not store_on_device and self.has_stored_key):
            # Ensure we have access to protected data before overwriting key
            try:
                self._init_pivman_protected()
            except Exception as e:
                logger.debug("Failed to initialize protected pivman data", exc_info=e)

                if store_on_device:
                    raise

        # Set the new management key
        self._app.set_management_key(new_key)

        if self.has_derived_key:
            # Clear salt for old derived keys.
            self._pivman_data.salt = None
        # Set flag for stored or not stored key.
        self._pivman_data.mgm_key_protected = store_on_device
        # Update readable pivman data
        self.put_data(OBJECT_ID_PIVMAN_DATA, self._pivman_data.get_bytes())
        if store_on_device:
            # Store key in protected pivman data
            self._pivman_protected_data.key = new_key
            self.put_data(
                OBJECT_ID_PIVMAN_PROTECTED_DATA, self._pivman_protected_data.get_bytes()
            )
        elif not store_on_device and self.has_stored_key:
            # If new key should not be stored and there is an old stored key,
            # try to clear it.
            try:
                self._pivman_protected_data.key = None
                self.put_data(
                    OBJECT_ID_PIVMAN_PROTECTED_DATA,
                    self._pivman_protected_data.get_bytes(),
                )
            except ApduError as e:
                logger.debug("No PIN provided, can't clear key..", exc_info=e)
        # Update CHUID and CCC if not set
        try:
            self.get_data(OBJECT_ID.CAPABILITY)
        except ApduError as e:
            if e.sw == SW.FILE_NOT_FOUND:
                self.update_ccc()
            else:
                logger.debug("Failed to read CCC...", exc_info=e)
        try:
            self.get_data(OBJECT_ID.CHUID)
        except ApduError as e:
            if e.sw == SW.FILE_NOT_FOUND:
                self.update_chuid()
            else:
                logger.debug("Failed to read CHUID...", exc_info=e)

    def get_pin_tries(self):
        """
        Returns the number of PIN retries left,
        0 PIN authentication blocked. Note that 15 is the highest
        value that will be returned even if remaining tries is higher.
        """
        return self._app.get_pin_attempts()

    def reset(self):
        self._app.reset()
        self._update_pivman_data()

    def get_data(self, object_id):
        return self._app.get_object(object_id)

    def put_data(self, object_id, data):
        self._app.put_object(object_id, data)

    def generate_key(
        self,
        slot,
        algorithm,
        pin_policy=PIN_POLICY.DEFAULT,
        touch_policy=TOUCH_POLICY.DEFAULT,
    ):
        if KEY_TYPE(algorithm).algorithm == ALGORITHM.RSA:
            ensure_not_cve201715361_vulnerable_firmware_version(self.version)

        return self._app.generate_key(slot, algorithm, pin_policy, touch_policy)

    def generate_self_signed_certificate(
        self, slot, public_key, common_name, valid_from, valid_to, touch_callback=None
    ):

        key_type = KEY_TYPE.from_public_key(public_key)

        builder = x509.CertificateBuilder()
        builder = builder.public_key(public_key)
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )

        # Same as subject on self-signed certificates.
        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )

        # x509.random_serial_number added in cryptography 1.6
        serial = int_from_bytes(os.urandom(20), "big") >> 1
        builder = builder.serial_number(serial)

        builder = builder.not_valid_before(valid_from)
        builder = builder.not_valid_after(valid_to)

        try:
            cert = self.sign_cert_builder(slot, key_type, builder, touch_callback)
        except ApduError as e:
            logger.error("Failed to generate certificate for slot %s", slot, exc_info=e)
            raise

        self.import_certificate(slot, cert, verify=False)

    def generate_certificate_signing_request(
        self, slot, public_key, subject, touch_callback=None
    ):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
        )

        try:
            return self.sign_csr_builder(
                slot, public_key, builder, touch_callback=touch_callback
            )
        except ApduError as e:
            logger.error(
                "Failed to generate Certificate Signing Request for slot %s",
                slot,
                exc_info=e,
            )
            raise

    def import_key(
        self,
        slot,
        key,
        pin_policy=PIN_POLICY.DEFAULT,
        touch_policy=TOUCH_POLICY.DEFAULT,
    ):
        return self._app.put_key(slot, key, pin_policy, touch_policy)

    def import_certificate(self, slot, certificate, verify=False, touch_callback=None):
        if verify:
            # Verify that the public key used in the certificate
            # is from the same keypair as the private key.
            try:
                public_key = certificate.public_key()

                test_data = b"test"

                if touch_callback is not None:
                    touch_timer = Timer(0.500, touch_callback)
                    touch_timer.start()

                try:
                    test_sig = self._app.sign(
                        slot,
                        KEY_TYPE.from_public_key(public_key),
                        test_data,
                        hashes.SHA256(),
                        padding.PKCS1v15(),  # Only used for RSA
                    )
                finally:
                    if touch_callback is not None:
                        touch_timer.cancel()

                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        test_sig, test_data, padding.PKCS1v15(), hashes.SHA256(),
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(test_sig, test_data, ec.ECDSA(hashes.SHA256()))
                else:
                    raise ValueError("Unknown key type: " + type(public_key))

            except ApduError as e:
                if e.sw == SW.INCORRECT_PARAMETERS:
                    raise KeypairMismatch(slot, certificate)
                raise

            except InvalidSignature:
                raise KeypairMismatch(slot, certificate)

        self._app.put_certificate(slot, certificate)
        self.update_chuid()

    def read_certificate(self, slot):
        return self._app.get_certificate(slot)

    def delete_certificate(self, slot):
        return self._app.delete_certificate(slot)

    def attest(self, slot):
        return self._app.attest_key(slot)

    def list_certificates(self):
        certs = OrderedDict()
        for slot in set(SLOT) - {SLOT.CARD_MANAGEMENT, SLOT.ATTESTATION}:
            try:
                certs[slot] = self.read_certificate(slot)
            except ApduError:
                pass
            except BadResponseError:
                certs[slot] = None

        return certs

    def update_chuid(self):
        # Non-Federal Issuer FASC-N
        # [9999-9999-999999-0-1-0000000000300001]
        FASC_N = (
            b"\xd4\xe7\x39\xda\x73\x9c\xed\x39\xce\x73\x9d\x83\x68"
            + b"\x58\x21\x08\x42\x10\x84\x21\xc8\x42\x10\xc3\xeb"
        )
        # Expires on: 2030-01-01
        EXPIRY = b"\x32\x30\x33\x30\x30\x31\x30\x31"

        self.put_data(
            OBJECT_ID.CHUID,
            Tlv(0x30, FASC_N)
            + Tlv(0x34, os.urandom(16))
            + Tlv(0x35, EXPIRY)
            + Tlv(0x3E)
            + Tlv(TAG_LRC),
        )

    def update_ccc(self):
        self.put_data(
            OBJECT_ID.CAPABILITY,
            Tlv(0xF0, b"\xa0\x00\x00\x01\x16\xff\x02" + os.urandom(14))
            + Tlv(0xF1, b"\x21")
            + Tlv(0xF2, b"\x21")
            + Tlv(0xF3)
            + Tlv(0xF4, b"\x00")
            + Tlv(0xF5, b"\x10")
            + Tlv(0xF6)
            + Tlv(0xF7)
            + Tlv(0xFA)
            + Tlv(0xFB)
            + Tlv(0xFC)
            + Tlv(0xFD)
            + Tlv(TAG_LRC),
        )

    def sign_cert_builder(self, slot, key_type, builder, touch_callback=None):
        dummy_key = _dummy_key(key_type)
        cert = builder.sign(dummy_key, hashes.SHA256(), default_backend())

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        sig = self._app.sign(
            slot,
            key_type,
            cert.tbs_certificate_bytes,
            hashes.SHA256(),
            padding.PKCS1v15(),  # Only used for RSA
        )

        if touch_callback is not None:
            touch_timer.cancel()

        seq = Tlv.parse_list(Tlv.unwrap(0x30, cert.public_bytes(Encoding.DER)))
        # Replace signature, add unused bits = 0
        seq[2] = Tlv(seq[2].tag, b"\0" + sig)
        # Re-assemble sequence
        der = Tlv(0x30, b"".join(seq))

        return x509.load_der_x509_certificate(der, default_backend())

    def sign_csr_builder(self, slot, public_key, builder, touch_callback=None):
        key_type = KEY_TYPE.from_public_key(public_key)
        dummy_key = _dummy_key(key_type)
        csr = builder.sign(dummy_key, hashes.SHA256(), default_backend())
        seq = Tlv.parse_list(Tlv.unwrap(0x30, csr.public_bytes(Encoding.DER)))

        # Replace public key
        pub_format = (
            PublicFormat.PKCS1
            if key_type.algorithm == ALGORITHM.RSA
            else PublicFormat.SubjectPublicKeyInfo
        )
        dummy_bytes = dummy_key.public_key().public_bytes(Encoding.DER, pub_format)
        pub_bytes = public_key.public_bytes(Encoding.DER, pub_format)
        seq[0] = seq[0].replace(dummy_bytes, pub_bytes)

        if touch_callback is not None:
            touch_timer = Timer(0.500, touch_callback)
            touch_timer.start()

        sig = self._app.sign(
            slot,
            key_type,
            seq[0],
            hashes.SHA256(),
            padding.PKCS1v15(),  # Only used for RSA
        )

        if touch_callback is not None:
            touch_timer.cancel()

        # Replace signature, add unused bits = 0
        seq[2] = Tlv(seq[2].tag, b"\0" + sig)
        # Re-assemble sequence
        der = Tlv(0x30, b"".join(seq))

        return x509.load_der_x509_csr(der, default_backend())

    @property
    def supports_pin_policies(self):
        return self.version >= (4, 0, 0)

    @property
    def supported_touch_policies(self):
        if self.version < (4, 0, 0):
            return []  # Touch policy not supported on NEO.
        elif self.version < (4, 3, 0):
            return [
                TOUCH_POLICY.DEFAULT,
                TOUCH_POLICY.NEVER,
                TOUCH_POLICY.ALWAYS,
            ]  # Cached policy was added in 4.3
        else:
            return [policy for policy in TOUCH_POLICY]

    @property
    def supported_algorithms(self):
        return [
            key_type
            for key_type in KEY_TYPE
            if not (
                key_type.algorithm == ALGORITHM.RSA
                and is_cve201715361_vulnerable_firmware_version(self.version)
            )
            if not (key_type == KEY_TYPE.ECCP384 and self.version < (4, 0, 0))
            if not (key_type == KEY_TYPE.RSA1024 and is_fips_version(self.version))
        ]
