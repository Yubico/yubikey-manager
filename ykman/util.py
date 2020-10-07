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

import struct
import re
import logging
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from base64 import b32decode
from OpenSSL import crypto
from .scancodes import KEYBOARD_LAYOUT
from yubikit.core import Tlv


logger = logging.getLogger(__name__)


PEM_IDENTIFIER = b"-----BEGIN"


class Cve201715361VulnerableError(Exception):
    """Thrown if on-chip RSA key generation is attempted on a YubiKey vulnerable
    to CVE-2017-15361."""

    def __init__(self, f_version):
        self.f_version = f_version

    def __str__(self):
        return (
            "On-chip RSA key generation on this YubiKey has been blocked.\n"
            "Please see https://yubi.co/ysa201701 for details."
        )


parse_tlvs = Tlv.parse_list  # Deprecated, use Tlv.parse_list directly


class MissingLibrary(object):
    def __init__(self, message):
        self._message = message

    def __getattr__(self, name):
        raise AttributeError(self._message)


_MODHEX = "cbdefghijklnrtuv"
DEFAULT_PW_CHAR_BLOCKLIST = ["\t", "\n", " "]


def modhex_encode(data):
    return "".join(_MODHEX[b >> 4] + _MODHEX[b & 0xF] for b in data)


def modhex_decode(string):
    return bytes(
        _MODHEX.index(string[i]) << 4 | _MODHEX.index(string[i + 1])
        for i in range(0, len(string), 2)
    )


def ensure_not_cve201715361_vulnerable_firmware_version(f_version):
    if is_cve201715361_vulnerable_firmware_version(f_version):
        raise Cve201715361VulnerableError(f_version)


def is_cve201715361_vulnerable_firmware_version(f_version):
    return (4, 2, 0) <= f_version < (4, 3, 5)


def generate_static_pw(
    length, keyboard_layout=KEYBOARD_LAYOUT.MODHEX, blocklist=DEFAULT_PW_CHAR_BLOCKLIST
):
    chars = [k for k in keyboard_layout.value.keys() if k not in blocklist]
    sr = random.SystemRandom()
    return "".join([sr.choice(chars) for _ in range(length)])


def format_code(code, digits=6, steam=False):
    STEAM_CHAR_TABLE = "23456789BCDFGHJKMNPQRTVWXY"
    if steam:
        chars = []
        for i in range(5):
            chars.append(STEAM_CHAR_TABLE[code % len(STEAM_CHAR_TABLE)])
            code //= len(STEAM_CHAR_TABLE)
        return "".join(chars)
    else:
        return ("%%0%dd" % digits) % (code % 10 ** digits)


def parse_totp_hash(resp):
    offs = resp[-1] & 0xF
    return parse_truncated(resp[offs : offs + 4])


def parse_truncated(resp):
    return struct.unpack(">I", resp)[0] & 0x7FFFFFFF


def hmac_shorten_key(key, algo):
    if algo.upper() == "SHA1":
        h = hashes.SHA1()  # nosec
    elif algo.upper() == "SHA256":
        h = hashes.SHA256()
    elif algo.upper() == "SHA512":
        h = hashes.SHA512()
    else:
        raise ValueError("Unsupported algorithm!")

    if len(key) > h.block_size:
        h = hashes.Hash(h, default_backend())
        h.update(key)
        key = h.finalize()
    return key


def time_challenge(timestamp, period=30):
    return struct.pack(">q", int(timestamp // period))


def parse_key(val):
    val = val.upper()
    if re.match(r"^([0-9A-F]{2})+$", val):  # hex
        return bytes.fromhex(val)
    else:
        # Key should be b32 encoded
        return parse_b32_key(val)


def parse_b32_key(key):
    key = key.upper().replace(" ", "")
    key += "=" * (-len(key) % 8)  # Support unpadded
    return b32decode(key)


def parse_private_key(data, password):
    """
    Identifies, decrypts and returns a cryptography private key object.
    """
    # PEM
    if is_pem(data):
        if b"ENCRYPTED" in data:
            if password is None:
                raise TypeError("No password provided for encrypted key.")
        try:
            return serialization.load_pem_private_key(
                data, password, backend=default_backend()
            )
        except ValueError:
            # Cryptography raises ValueError if decryption fails.
            raise
        except Exception as e:
            logger.debug("Failed to parse PEM private key ", exc_info=e)

    # PKCS12
    if is_pkcs12(data):
        try:
            p12 = crypto.load_pkcs12(data, password)
            data = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
            return serialization.load_pem_private_key(
                data, password=None, backend=default_backend()
            )
        except crypto.Error as e:
            raise ValueError(e)

    # DER
    try:
        return serialization.load_der_private_key(
            data, password, backend=default_backend()
        )
    except Exception as e:
        logger.debug("Failed to parse private key as DER", exc_info=e)

    # All parsing failed
    raise ValueError("Could not parse private key.")


def parse_certificates(data, password):
    """
    Identifies, decrypts and returns list of cryptography x509 certificates.
    """

    # PEM
    if is_pem(data):
        certs = []
        for cert in data.split(PEM_IDENTIFIER):
            try:
                certs.append(
                    x509.load_pem_x509_certificate(
                        PEM_IDENTIFIER + cert, default_backend()
                    )
                )
            except Exception as e:
                logger.debug("Failed to parse PEM certificate", exc_info=e)
        # Could be valid PEM but not certificates.
        if len(certs) > 0:
            return certs

    # PKCS12
    if is_pkcs12(data):
        try:
            p12 = crypto.load_pkcs12(data, password)
            data = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
            return [x509.load_pem_x509_certificate(data, default_backend())]
        except crypto.Error as e:
            raise ValueError(e)

    # DER
    try:
        return [x509.load_der_x509_certificate(data, default_backend())]
    except Exception as e:
        logger.debug("Failed to parse certificate as DER", exc_info=e)

    raise ValueError("Could not parse certificate.")


def get_leaf_certificates(certs):
    """
    Extracts the leaf certificates from a list of certificates. Leaf
    certificates are ones whose subject does not appear as issuer among the
    others.
    """
    issuers = [
        cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) for cert in certs
    ]
    leafs = [
        cert
        for cert in certs
        if (
            cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) not in issuers
        )
    ]
    return leafs


def is_pem(data):
    return PEM_IDENTIFIER in data if data else False


def is_pkcs12(data):
    """
    Tries to identify a PKCS12 container.
    The PFX PDU version is assumed to be v3.
    See: https://tools.ietf.org/html/rfc7292.
    """
    if isinstance(data, bytes):
        tlv = Tlv(data)
        if tlv.tag == 0x30:
            header = Tlv(tlv.value)
            return header.tag == 0x02 and header.value == b"\x03"
        return False
    else:
        return False
