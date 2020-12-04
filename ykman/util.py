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

import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from OpenSSL import crypto
from yubikit.core import Tlv


logger = logging.getLogger(__name__)


PEM_IDENTIFIER = b"-----BEGIN"


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
    try:
        header = Tlv.parse_list(Tlv.unpack(0x30, data))[0]
        return header.tag == 0x02 and header.value == b"\x03"
    except ValueError:
        return False
