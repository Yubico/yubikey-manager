# -*- coding: utf-8 -*-

# Copyright (c) 2019 Yubico AB
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
import six

from enum import IntEnum
from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

from .utils import bytes2int, ByteBuffer


if six.PY2:
    # Workaround for int max size on Python 2.
    from enum import Enum

    class _LongEnum(long, Enum):  # noqa F821
        """Like IntEnum, but supports larger values"""

    IntEnum = _LongEnum  # Use instead of IntEnum  # noqa F811


TPM_ALG_NULL = 0x0010


class TpmRsaScheme(IntEnum):
    RSASSA = 0x0014
    RSAPSS = 0x0016
    OAEP = 0x0017
    RSAES = 0x0015


class TpmAlgAsym(IntEnum):
    RSA = 0x0001
    ECC = 0x0023


class TpmAlgHash(IntEnum):
    SHA1 = 0x0004
    SHA256 = 0x000B
    SHA384 = 0x000C
    SHA512 = 0x000D

    def _hash_alg(self):
        if self == TpmAlgHash.SHA1:
            return hashes.SHA1()
        elif self == TpmAlgHash.SHA256:
            return hashes.SHA256()
        elif self == TpmAlgHash.SHA384:
            return hashes.SHA384()
        elif self == TpmAlgHash.SHA512:
            return hashes.SHA512()

        return NotImplementedError(
            "_hash_alg is not implemented for {0!r}".format(self)
        )


TpmsCertifyInfo = namedtuple("TpmsCertifyInfo", "name qualified_name")


class TpmAttestationFormat(object):
    """the signature data is defined by [TPMv2-Part2] Section 10.12.8 (TPMS_ATTEST)
    as:
      TPM_GENERATED_VALUE (0xff544347 aka "\xffTCG")
      TPMI_ST_ATTEST - always TPM_ST_ATTEST_CERTIFY (0x8017)
        because signing procedure defines it should call TPM_Certify
        [TPMv2-Part3] Section 18.2
      TPM2B_NAME
        size (uint16)
        name (size long)
      TPM2B_DATA
        size (uint16)
        name (size long)
      TPMS_CLOCK_INFO
        clock (uint64)
        resetCount (uint32)
        restartCount (uint32)
        safe (byte) 1 yes, 0 no
      firmwareVersion uint64
      attested TPMS_CERTIFY_INFO (because TPM_ST_ATTEST_CERTIFY)
        name TPM2B_NAME
        qualified_name TPM2B_NAME
    See:
      https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
      https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
    """

    TPM_GENERATED_VALUE = b"\xffTCG"
    TPM_ST_ATTEST_CERTIFY = b"\x80\x17"

    @classmethod
    def parse(cls, data):
        reader = ByteBuffer(data)
        generated_value = reader.read(4)

        # Verify that magic is set to TPM_GENERATED_VALUE.
        # see https://w3c.github.io/webauthn/#sctn-tpm-attestation
        #     verification procedure
        if generated_value != cls.TPM_GENERATED_VALUE:
            raise ValueError("generated value field is invalid")

        # Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        # see https://w3c.github.io/webauthn/#sctn-tpm-attestation
        #     verification procedure
        tpmi_st_attest = reader.read(2)
        if tpmi_st_attest != cls.TPM_ST_ATTEST_CERTIFY:
            raise ValueError("tpmi_st_attest field is invalid")

        try:
            name = reader.read(reader.unpack("!H"))
            data = reader.read(reader.unpack("!H"))

            clock = reader.unpack("!Q")
            reset_count = reader.unpack("!L")
            restart_count = reader.unpack("!L")
            safe_value = reader.unpack("B")
            if safe_value not in (0, 1):
                raise ValueError("invalid value 0x{0:x} for boolean".format(safe_value))
            safe = safe_value == 1

            firmware_version = reader.unpack("!Q")

            attested_name = reader.read(reader.unpack("!H"))
            attested_qualified_name = reader.read(reader.unpack("!H"))
        except struct.error as e:
            raise ValueError(e)

        return cls(
            name=name,
            data=data,
            clock_info=(clock, reset_count, restart_count, safe),
            firmware_version=firmware_version,
            attested=TpmsCertifyInfo(
                name=attested_name, qualified_name=attested_qualified_name
            ),
        )

    def __init__(self, name, data, clock_info, firmware_version, attested):
        self.name = name
        self.data = data
        self.clock_info = clock_info
        self.firmware_version = firmware_version
        assert attested.__class__ == TpmsCertifyInfo
        self.attested = attested

    def __repr__(self):
        return (
            "<TpmAttestationFormat"
            " data={self.data}"
            " name={self.name}"
            " clock_info={self.clock_info}"
            " firmware_version=0x{self.firmware_version:x}"
            " attested={self.attested}"
            ">".format(self=self)
        )


class TpmsRsaParms(object):
    """ Parse TPMS_RSA_PARMS struct

    See:
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    section 12.2.3.5
    """

    @classmethod
    def parse(cls, reader, attributes):
        ATTRIBUTES = TpmPublicFormat.ATTRIBUTES

        symmetric = reader.unpack("!H")

        restricted_decryption = attributes & (
            ATTRIBUTES.RESTRICTED | ATTRIBUTES.DECRYPT
        )
        is_restricted_decryption_key = restricted_decryption == (
            ATTRIBUTES.DECRYPT | ATTRIBUTES.RESTRICTED
        )
        if not is_restricted_decryption_key and symmetric != TPM_ALG_NULL:
            # if the key is not a restricted decryption key, this field
            # shall be set to TPM_ALG_NULL.
            raise ValueError("symmetric is expected to be NULL")
        # Otherwise should be set to a supported symmetric algorithm, keysize and mode
        # TODO(baloo): Should we have non-null value here, do we expect more data?

        scheme = reader.unpack("!H")

        restricted_sign = attributes & (ATTRIBUTES.RESTRICTED | ATTRIBUTES.SIGN_ENCRYPT)
        is_unrestricted_signing_key = restricted_sign == ATTRIBUTES.SIGN_ENCRYPT
        if is_unrestricted_signing_key and scheme not in (
            TPM_ALG_NULL,
            TpmRsaScheme.RSASSA,
            TpmRsaScheme.RSAPSS,
        ):
            raise ValueError(
                "key is an unrestricted signing key, scheme is "
                "expected to be TPM_ALG_RSAPSS, TPM_ALG_RSASSA, "
                "or TPM_ALG_NULL"
            )

        is_restricted_signing_key = restricted_sign == (
            ATTRIBUTES.RESTRICTED | ATTRIBUTES.SIGN_ENCRYPT
        )
        if is_restricted_signing_key and scheme not in (
            TpmRsaScheme.RSASSA,
            TpmRsaScheme.RSAPSS,
        ):
            raise ValueError(
                "key is a restricted signing key, scheme is "
                "expected to be TPM_ALG_RSAPSS, or TPM_ALG_RSASSA"
            )

        is_unrestricted_decryption_key = restricted_decryption == ATTRIBUTES.DECRYPT
        if is_unrestricted_decryption_key and scheme not in (
            TpmRsaScheme.OAEP,
            TpmRsaScheme.RSAES,
            TPM_ALG_NULL,
        ):
            raise ValueError(
                "key is an unrestricted decryption key, scheme is "
                "expected to be TPM_ALG_RSAES, TPM_ALG_OAEP, or "
                "TPM_ALG_NULL"
            )

        if is_restricted_decryption_key and scheme not in (TPM_ALG_NULL,):
            raise ValueError(
                "key is an restricted decryption key, scheme is "
                "expected to be TPM_ALG_NULL"
            )

        key_bits = reader.unpack("!H")
        exponent = reader.unpack("!L")
        if exponent == 0:
            # When  zero,  indicates  that  the  exponent  is  the  default  of 2^16 + 1
            exponent = (2 ** 16) + 1

        return cls(symmetric, scheme, key_bits, exponent)

    def __init__(self, symmetric, scheme, key_bits, exponent):
        self.symmetric = symmetric
        self.scheme = scheme
        self.key_bits = key_bits
        self.exponent = exponent

    def __repr__(self):
        return (
            "<TpmsRsaParms"
            " symmetric=0x{self.symmetric:x}"
            " scheme=0x{self.scheme:x}"
            " key_bits={self.key_bits}"
            " exponent={self.exponent}"
            ">".format(self=self)
        )


class Tpm2bPublicKeyRsa(bytes):
    @classmethod
    def parse(cls, reader):
        buffer = reader.read(reader.unpack("!H"))

        return cls(buffer)


class TpmEccCurve(IntEnum):
    """TPM_ECC_CURVE
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    section 6.4
    """

    NONE = 0x0000
    NIST_P192 = 0x0001
    NIST_P224 = 0x0002
    NIST_P256 = 0x0003
    NIST_P384 = 0x0004
    NIST_P521 = 0x0005
    BN_P256 = 0x0010
    BN_P638 = 0x0011
    SM2_P256 = 0x0020

    def to_curve(self):
        if self == TpmEccCurve.NONE:
            raise ValueError("No such curve")
        elif self == TpmEccCurve.NIST_P192:
            return ec.SECP192R1()
        elif self == TpmEccCurve.NIST_P224:
            return ec.SECP224R1()
        elif self == TpmEccCurve.NIST_P256:
            return ec.SECP256R1()
        elif self == TpmEccCurve.NIST_P384:
            return ec.SECP384R1()
        elif self == TpmEccCurve.NIST_P521:
            return ec.SECP521R1()

        raise ValueError("curve is not supported", self)


class TpmiAlgKdf(IntEnum):
    """TPMI_ALG_KDF
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    section 9.28
    """

    NULL = TPM_ALG_NULL
    KDF1_SP800_56A = 0x0020
    KDF2 = 0x0021
    KDF1_SP800_108 = 0x0022


class TpmsEccParms(object):
    @classmethod
    def parse(cls, reader):
        symmetric = reader.unpack("!H")
        scheme = reader.unpack("!H")
        if symmetric != TPM_ALG_NULL:
            raise ValueError("symmetric is expected to be NULL")
        if scheme != TPM_ALG_NULL:
            raise ValueError("scheme is expected to be NULL")

        curve_id = TpmEccCurve(reader.unpack("!H"))
        kdf_scheme = TpmiAlgKdf(reader.unpack("!H"))

        return cls(symmetric, scheme, curve_id, kdf_scheme)

    def __init__(self, symmetric, scheme, curve_id, kdf):
        self.symmetric = symmetric
        self.scheme = scheme
        self.curve_id = curve_id
        self.kdf = kdf

    def __repr__(self):
        return (
            "<TpmsEccParms"
            " symmetric=0x{self.symmetric:x}"
            " scheme=0x{self.scheme:x}"
            " curve_id={self.curve_id!r}"
            " kdf={self.kdf!r}"
            ">".format(self=self)
        )


class TpmsEccPoint(object):
    """TPMS_ECC_POINT
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    Section 11.2.5.2
    """

    @classmethod
    def parse(cls, reader):
        x = reader.read(reader.unpack("!H"))
        y = reader.read(reader.unpack("!H"))

        return cls(x, y)

    def __init__(self, x, y):
        self.x = y
        self.y = y

    def __repr__(self):
        return "<TpmsEccPoint" " x={self.x}" " y={self.y}" ">".format(self=self)


class TpmPublicFormat(object):
    """the public area structure is defined by [TPMv2-Part2] Section 12.2.4 (TPMT_PUBLIC)
    as:
      TPMI_ALG_PUBLIC - type
      TPMI_ALG_HASH - nameAlg
        or + to indicate TPM_ALG_NULL
      TPMA_OBJECT - objectAttributes
      TPM2B_DIGEST - authPolicy
      TPMU_PUBLIC_PARMS - type parameters
      TPMU_PUBLIC_ID - uniq
    See:
      https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    """

    class ATTRIBUTES(IntEnum):
        """Object attributes
        see section 8.3
          https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
        """

        FIXED_TPM = 1 << 1
        ST_CLEAR = 1 << 2
        FIXED_PARENT = 1 << 4
        SENSITIVE_DATA_ORIGIN = 1 << 5
        USER_WITH_AUTH = 1 << 6
        ADMIN_WITH_POLICY = 1 << 7
        NO_DA = 1 << 10
        ENCRYPTED_DUPLICATION = 1 << 11
        RESTRICTED = 1 << 16
        DECRYPT = 1 << 17
        SIGN_ENCRYPT = 1 << 18

        SHALL_BE_ZERO = (
            (1 << 0)  # 0 Reserved
            | (1 << 3)  # 3 Reserved
            | (0x3 << 8)  # 9:8 Reserved
            | (0xF << 12)  # 15:12 Reserved
            | ((0xFFFFFFFF << 19) & (2 ** 32 - 1))  # 31:19 Reserved
        )

    @classmethod
    def parse(cls, data):
        reader = ByteBuffer(data)
        sign_alg = TpmAlgAsym(reader.unpack("!H"))
        name_alg = TpmAlgHash(reader.unpack("!H"))

        attributes = reader.unpack("!L")
        if attributes & TpmPublicFormat.ATTRIBUTES.SHALL_BE_ZERO != 0:
            raise ValueError(
                "attributes is not formated correctly: 0x{:x}".format(attributes)
            )

        auth_policy = reader.read(reader.unpack("!H"))

        if sign_alg == TpmAlgAsym.RSA:
            parameters = TpmsRsaParms.parse(reader, attributes)
            unique = Tpm2bPublicKeyRsa.parse(reader)
        elif sign_alg == TpmAlgAsym.ECC:
            parameters = TpmsEccParms.parse(reader)
            unique = TpmsEccPoint.parse(reader)
        else:
            raise NotImplementedError(
                "sign alg {:x} is not " "supported".format(sign_alg)
            )

        rest = reader.read()
        if len(rest) != 0:
            raise ValueError("there should not be any data left in buffer")

        return cls(
            sign_alg, name_alg, attributes, auth_policy, parameters, unique, data
        )

    def __init__(
        self, sign_alg, name_alg, attributes, auth_policy, parameters, unique, data
    ):
        self.sign_alg = sign_alg
        self.name_alg = name_alg
        self.attributes = attributes
        self.auth_policy = auth_policy
        self.parameters = parameters
        self.unique = unique
        self.data = data

    def __repr__(self):
        return (
            "<TpmPublicFormat"
            " sign_alg=0x{self.sign_alg:x}"
            " name_alg=0x{self.name_alg:x}"
            " attributes=0x{self.attributes:x}({self.attributes!r})"
            " auth_policy={self.auth_policy}"
            " parameters={self.parameters}"
            " unique={self.unique}"
            ">".format(self=self)
        )

    def public_key(self):
        if self.sign_alg == TpmAlgAsym.RSA:
            exponent = self.parameters.exponent
            modulus = bytes2int(self.unique)
            return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
        elif self.sign_alg == TpmAlgAsym.ECC:
            return ec.EllipticCurvePublicNumbers(
                bytes2int(self.unique.x),
                bytes2int(self.unique.y),
                self.parameters.to_curve(),
            ).public_key(default_backend())

        raise NotImplementedError(
            "public_key not implemented for {0!r}".format(self.sign_alg)
        )

    def name(self):
        """
        Computing Entity Names

        see:
          https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
        section 16 Names

        Name ≔ nameAlg || HnameAlg (handle→nvPublicArea)
          where
            nameAlg algorithm used to compute Name
            HnameAlg hash using the nameAlg parameter in the NV Index location
                     associated with handle
            nvPublicArea contents of the TPMS_NV_PUBLIC associated with handle
        """
        output = struct.pack("!H", self.name_alg)

        digest = hashes.Hash(self.name_alg._hash_alg(), backend=default_backend())
        digest.update(self.data)
        output += digest.finalize()

        return output
