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

from yubikit.core import Tlv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from functools import partial
from typing import Tuple
import ctypes

import logging


logger = logging.getLogger(__name__)


PEM_IDENTIFIER = b"-----BEGIN"


def _parse_pkcs12_cryptography(pkcs12, data, password):
    key, cert, cas = pkcs12.load_key_and_certificates(data, password, default_backend())
    return key, [cert] + cas


def _parse_pkcs12_pyopenssl(crypto, data, password):
    try:
        p12 = crypto.load_pkcs12(data, password)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        key = serialization.load_pem_private_key(
            key_pem, password=None, backend=default_backend()
        )

        certs = [p12.get_certificate()]
        cas = p12.get_ca_certificates()
        if cas:
            certs.extend(cas)
        certs_pem = [
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert) for cert in certs
        ]
        certs = [
            x509.load_pem_x509_certificate(cert_pem, default_backend())
            for cert_pem in certs_pem
        ]
        return key, certs
    except crypto.Error as e:
        raise ValueError(e)


def _parse_pkcs12_unsupported(data, password):
    raise ValueError("PKCS#12 support requires cryptography >= 2.5 or pyOpenSSL")


try:  # This requires cryptography 2.5.
    from cryptography.hazmat.primitives.serialization import pkcs12

    _parse_pkcs12 = partial(_parse_pkcs12_cryptography, pkcs12)
except ImportError:  # Use pyOpenSSL as a backup
    try:
        from OpenSSL import crypto

        _parse_pkcs12 = partial(_parse_pkcs12_pyopenssl, crypto)
    except ImportError:  # Can't support PKCS#12
        _parse_pkcs12 = _parse_pkcs12_unsupported  # type: ignore


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
        return _parse_pkcs12(data, password)[0]

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
            if cert:
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
        return _parse_pkcs12(data, password)[1]

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
    try:
        header = Tlv.parse_list(Tlv.unpack(0x30, data))[0]
        return header.tag == 0x02 and header.value == b"\x03"
    except ValueError:
        return False


class OSVERSIONINFOW(ctypes.Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", ctypes.c_ulong),
        ("dwMajorVersion", ctypes.c_ulong),
        ("dwMinorVersion", ctypes.c_ulong),
        ("dwBuildNumber", ctypes.c_ulong),
        ("dwPlatformId", ctypes.c_ulong),
        ("szCSDVersion", ctypes.c_wchar * 128),
    ]


def get_windows_version() -> Tuple[int, int, int]:
    """Get the true Windows version, since sys.getwindowsversion lies."""
    osvi = OSVERSIONINFOW()
    osvi.dwOSVersionInfoSize = ctypes.sizeof(osvi)
    ctypes.windll.Ntdll.RtlGetVersion(ctypes.byref(osvi))  # type: ignore
    return osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber
