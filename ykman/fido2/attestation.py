# Copyright (c) 2018 Yubico AB
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

from __future__ import absolute_import, unicode_literals

from .cose import CoseKey, ES256
from ._tpm import TpmAttestationFormat, TpmPublicFormat
from .utils import sha256, websafe_decode
from binascii import a2b_hex
from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives import hashes
import abc
import json


class InvalidAttestation(Exception):
    pass


class InvalidData(InvalidAttestation):
    pass


class InvalidSignature(InvalidAttestation):
    pass


class UnsupportedType(InvalidAttestation):
    def __init__(self, auth_data, fmt=None):
        super(UnsupportedType, self).__init__(
            'Attestation format "{}" is not supported'.format(fmt)
            if fmt
            else "This attestation format is not supported!"
        )
        self.auth_data = auth_data
        self.fmt = fmt


class Attestation(abc.ABC):
    @abc.abstractmethod
    def verify(self, statement, auth_data, client_data_hash):
        pass

    @staticmethod
    def for_type(fmt):
        for cls in Attestation.__subclasses__():
            if getattr(cls, "FORMAT", None) == fmt:
                return cls

        class TypedUnsupportedAttestation(UnsupportedAttestation):
            def __init__(self):
                super(TypedUnsupportedAttestation, self).__init__(fmt)

        return TypedUnsupportedAttestation


class UnsupportedAttestation(Attestation):
    def __init__(self, fmt=None):
        self.fmt = fmt

    def verify(self, statement, auth_data, client_data_hash):
        raise UnsupportedType(auth_data, self.fmt)


class NoneAttestation(Attestation):
    FORMAT = "none"

    def verify(self, statement, auth_data, client_data_hash):
        if statement != {}:
            raise InvalidData("None Attestation requires empty statement.")


class FidoU2FAttestation(Attestation):
    FORMAT = "fido-u2f"

    def verify(self, statement, auth_data, client_data_hash):
        cd = auth_data.credential_data
        pk = b"\x04" + cd.public_key[-2] + cd.public_key[-3]
        FidoU2FAttestation.verify_signature(
            auth_data.rp_id_hash,
            client_data_hash,
            cd.credential_id,
            pk,
            statement["x5c"][0],
            statement["sig"],
        )

    @staticmethod
    def verify_signature(
        app_param, client_param, key_handle, public_key, cert_bytes, signature
    ):
        m = b"\0" + app_param + client_param + key_handle + public_key
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        try:
            ES256.from_cryptography_key(cert.public_key()).verify(m, signature)
        except _InvalidSignature:
            raise InvalidSignature()


# GS Root R2 (https://pki.goog/)
_GSR2_DER = a2b_hex(
    b"308203ba308202a2a003020102020b0400000000010f8626e60d300d06092a864886f70d0101050500304c3120301e060355040b1317476c6f62616c5369676e20526f6f74204341202d20523231133011060355040a130a476c6f62616c5369676e311330110603550403130a476c6f62616c5369676e301e170d3036313231353038303030305a170d3231313231353038303030305a304c3120301e060355040b1317476c6f62616c5369676e20526f6f74204341202d20523231133011060355040a130a476c6f62616c5369676e311330110603550403130a476c6f62616c5369676e30820122300d06092a864886f70d01010105000382010f003082010a0282010100a6cf240ebe2e6f28994542c4ab3e21549b0bd37f8470fa12b3cbbf875fc67f86d3b2305cd6fdadf17bdce5f86096099210f5d053defb7b7e7388ac52887b4aa6ca49a65ea8a78c5a11bc7a82ebbe8ce9b3ac962507974a992a072fb41e77bf8a0fb5027c1b96b8c5b93a2cbcd612b9eb597de2d006865f5e496ab5395e8834ecbc780c0898846ca8cd4bb4a07d0c794df0b82dcb21cad56c5b7de1a02984a1f9d39449cb24629120bcdd0bd5d9ccf9ea270a2b7391c69d1bacc8cbe8e0a0f42f908b4dfbb0361bf6197a85e06df26113885c9fe0930a51978a5aceafabd5f7aa09aa60bddcd95fdf72a960135e0001c94afa3fa4ea070321028e82ca03c29b8f0203010001a3819c308199300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e041604149be20757671c1ec06a06de59b49a2ddfdc19862e30360603551d1f042f302d302ba029a0278625687474703a2f2f63726c2e676c6f62616c7369676e2e6e65742f726f6f742d72322e63726c301f0603551d230418301680149be20757671c1ec06a06de59b49a2ddfdc19862e300d06092a864886f70d01010505000382010100998153871c68978691ece04ab8440bab81ac274fd6c1b81c4378b30c9afcea2c3c6e611b4d4b29f59f051d26c1b8e983006245b6a90893b9a9334b189ac2f887884edbdd71341ac154da463fe0d32aab6d5422f53a62cd206fba2989d7dd91eed35ca23ea15b41f5dfe564432de9d539abd2a2dfb78bd0c080191c45c02d8ce8f82da4745649c505b54f15de6e44783987a87ebbf3791891bbf46f9dc1f08c358c5d01fbc36db9ef446d7946317e0afea982c1ffefab6e20c450c95f9d4d9b178c0ce501c9a0416a7353faa550b46e250ffb4c18f4fd52d98e69b1e8110fde88d8fb1d49f7aade95cf2078c26012db25408c6afc7e4238406412f79e81e1932e"  # noqa E501
)


class AndroidSafetynetAttestation(Attestation):
    FORMAT = "android-safetynet"

    def __init__(self, allow_rooted=False, ca=_GSR2_DER):
        self.allow_rooted = allow_rooted
        self._ca = x509.load_der_x509_certificate(ca, default_backend())

    def verify(self, statement, auth_data, client_data_hash):
        jwt = statement["response"]
        header, payload, sig = (websafe_decode(x) for x in jwt.split(b"."))
        data = json.loads(payload.decode("utf8"))
        if not self.allow_rooted and data["ctsProfileMatch"] is not True:
            raise InvalidData("ctsProfileMatch must be true!")
        expected_nonce = sha256(auth_data + client_data_hash)
        if not bytes_eq(expected_nonce, websafe_decode(data["nonce"])):
            raise InvalidData("Nonce does not match!")

        data = json.loads(header.decode("utf8"))
        certs = [
            x509.load_der_x509_certificate(websafe_decode(x), default_backend())
            for x in data["x5c"]
        ]
        certs.append(self._ca)

        cert = certs.pop(0)
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn[0].value != "attest.android.com":
            raise InvalidData("Certificate not issued to attest.android.com!")

        CoseKey.for_name(data["alg"]).from_cryptography_key(cert.public_key()).verify(
            jwt.rsplit(b".", 1)[0], sig
        )

        while certs:
            child = cert
            cert = certs.pop(0)
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )


OID_AAGUID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


def _validate_cert_common(cert):
    if cert.version != x509.Version.v3:
        raise InvalidData("Attestation certificate must use version 3!")

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    if bc.value.ca:
        raise InvalidData("Attestation certificate must have CA=false!")


def _validate_packed_cert(cert, aaguid):
    # https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
    _validate_cert_common(cert)

    c = cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    if not c:
        raise InvalidData("Subject must have C set!")
    o = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if not o:
        raise InvalidData("Subject must have O set!")
    ous = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
    if not ous:
        raise InvalidData('Subject must have OU = "Authenticator Attestation"!')

    ou = ous[0]
    if ou.value != "Authenticator Attestation":
        raise InvalidData('Subject must have OU = "Authenticator Attestation"!')
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn:
        raise InvalidData("Subject must have CN set!")

    try:
        ext = cert.extensions.get_extension_for_oid(OID_AAGUID)
        if ext.critical:
            raise InvalidData("AAGUID extension must not be marked as critical")
        ext_aaguid = ext.value.value[2:]
        if ext_aaguid != aaguid:
            raise InvalidData(
                "AAGUID in Authenticator data does not "
                "match attestation certificate!"
            )
    except x509.ExtensionNotFound:
        pass  # If missing, ignore


class PackedAttestation(Attestation):
    FORMAT = "packed"

    def verify(self, statement, auth_data, client_data_hash):
        if "ecdaaKeyId" in statement:
            raise NotImplementedError("ECDAA not implemented")
        alg = statement["alg"]
        x5c = statement.get("x5c")
        if x5c:
            cert = x509.load_der_x509_certificate(x5c[0], default_backend())
            _validate_packed_cert(cert, auth_data.credential_data.aaguid)

            pub_key = CoseKey.for_alg(alg).from_cryptography_key(cert.public_key())
        else:
            pub_key = CoseKey.parse(auth_data.credential_data.public_key)
            if pub_key.ALGORITHM != alg:
                raise InvalidData("Wrong algorithm of public key!")
        try:
            pub_key.verify(auth_data + client_data_hash, statement["sig"])
        except _InvalidSignature:
            raise InvalidSignature()


OID_AIK_CERTIFICATE = x509.ObjectIdentifier("2.23.133.8.3")


def _validate_tpm_cert(cert):
    # https://www.w3.org/TR/webauthn/#tpm-cert-requirements
    _validate_cert_common(cert)

    s = cert.subject.get_attributes_for_oid(x509.NameOID)
    if s:
        raise InvalidData("Certificate should not have Subject")

    s = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if not s:
        raise InvalidData("Certificate should have SubjectAlternativeName")
    ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    has_aik = [x == OID_AIK_CERTIFICATE for x in ext.value]
    if True not in has_aik:
        raise InvalidData(
            'Extended key usage MUST contain the "joint-iso-itu-t(2) '
            "internationalorganizations(23) 133 tcg-kp(8) "
            'tcg-kp-AIKCertificate(3)" OID.'
        )


class TpmAttestation(Attestation):
    FORMAT = "tpm"

    def verify(self, statement, auth_data, client_data_hash):
        if "ecdaaKeyId" in statement:
            raise NotImplementedError("ECDAA not implemented")
        alg = statement["alg"]
        x5c = statement.get("x5c")
        cert_info = statement["certInfo"]
        if x5c:
            cert = x509.load_der_x509_certificate(x5c[0], default_backend())

            _validate_tpm_cert(cert)

            pub_key = CoseKey.for_alg(alg).from_cryptography_key(cert.public_key())
        else:
            pub_key = CoseKey.parse(auth_data.credential_data.public_key)
            if pub_key.ALGORITHM != alg:
                raise InvalidData("Wrong algorithm of public key!")

        try:
            pub_area = TpmPublicFormat.parse(statement["pubArea"])
        except Exception as e:
            raise InvalidData("unable to parse pubArea", e)

        # Verify that the public key specified by the parameters and unique
        # fields of pubArea is identical to the credentialPublicKey in the
        # attestedCredentialData in authenticatorData.
        if (
            auth_data.credential_data.public_key.from_cryptography_key(
                pub_area.public_key()
            )
            != auth_data.credential_data.public_key
        ):
            raise InvalidSignature(
                "attestation pubArea does not match attestedCredentialData"
            )

        try:
            # TpmAttestationFormat.parse is reponsible for:
            #   Verify that magic is set to TPM_GENERATED_VALUE.
            #   Verify that type is set to TPM_ST_ATTEST_CERTIFY.
            tpm = TpmAttestationFormat.parse(cert_info)

            # Verify that extraData is set to the hash of attToBeSigned
            # using the hash algorithm employed in "alg".
            att_to_be_signed = auth_data + client_data_hash
            digest = hashes.Hash(pub_key._HASH_ALG, backend=default_backend())
            digest.update(att_to_be_signed)
            data = digest.finalize()

            if tpm.data != data:
                raise InvalidSignature(
                    "attestation does not sign for authData and ClientData"
                )

            # Verify that attested contains a TPMS_CERTIFY_INFO structure as
            # specified in [TPMv2-Part2] section 10.12.3, whose name field
            # contains a valid Name for pubArea, as computed using the
            # algorithm in the nameAlg field of pubArea using the procedure
            # specified in [TPMv2-Part1] section 16.
            # [TPMv2-Part2]:
            # https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
            # [TPMv2-Part1]:
            # https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
            if tpm.attested.name != pub_area.name():
                raise InvalidData(
                    "TPMS_CERTIFY_INFO does not include a valid name for pubArea"
                )

            pub_key.verify(cert_info, statement["sig"])
        except _InvalidSignature:
            raise InvalidSignature("signature of certInfo does not match")
