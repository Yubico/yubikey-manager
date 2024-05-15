from .core import Tlv, int2bytes, BadResponseError
from .core.smartcard import (
    AID,
    SmartCardConnection,
    SmartCardProtocol,
    ApduError,
    SW,
    ScpProcessor,
)
from .core.smartcard.scp import (
    INS_INITIALIZE_UPDATE,
    INS_EXTERNAL_AUTHENTICATE,
    INS_INTERNAL_AUTHENTICATE,
    INS_PERFORM_SECURITY_OPERATION,
    ScpKeyParams,
    StaticKeys,
)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from dataclasses import dataclass
from typing import Mapping, Sequence, Union, Optional
from enum import IntEnum, unique


import logging

logger = logging.getLogger(__name__)


INS_GET_DATA = 0xCA
INS_PUT_KEY = 0xD8
INS_STORE_DATA = 0xE2
INS_DELETE = 0xE4
INS_GENERATE_KEY = 0xF1


@unique
class KeyType(IntEnum):
    AES = 0x88
    ECC_PUBLIC_KEY = 0xB0
    ECC_PRIVATE_KEY = 0xB1
    ECC_KEY_PARAMS = 0xF0


_DEFAULT_KCV_IV = b"\1" * 16


class ScpKey(bytes):
    @property
    def kid(self) -> int:
        return self[0]

    @property
    def kvn(self) -> int:
        return self[1]

    def __new__(cls, kid_or_data: Union[int, bytes], kvn: Optional[int] = None):
        """This allows creation by passing either binary data, or kid and kvn."""
        if isinstance(kid_or_data, int):  # kid and kvn
            if kvn is None:
                raise ValueError("Missing kvn")
            data = bytes([kid_or_data, kvn])
        else:  # Binary id and version
            if kvn is not None:
                raise ValueError("kvn can only be provided if kid_or_data is a kid")
            data = kid_or_data

        # mypy thinks this is wrong
        return super(ScpKey, cls).__new__(cls, data)  # type: ignore

    def __init__(self, kid_or_data: Union[int, bytes], kvn: Optional[int] = None):
        if len(self) != 2:
            raise ValueError("Incorrect length")

    def __repr__(self):
        return f"ScpKey(kid=0x{self.kid:02x}, kvn=0x{self.kvn:02x})"


@unique
class Curve(IntEnum):
    SECP256R1 = 0x00
    SECP384R1 = 0x01
    SECP521R1 = 0x02
    BrainpoolP256R1 = 0x03
    BrainpoolP384R1 = 0x05
    BrainpoolP512R1 = 0x07

    @classmethod
    def _from_key(cls, private_key: ec.EllipticCurvePrivateKey) -> "Curve":
        name = private_key.curve.name.lower()
        for curve in cls:
            if curve.name.lower() == name:
                return curve
        raise ValueError("Unsupported private key")

    @property
    def _curve(self) -> ec.EllipticCurve:
        return getattr(ec, self.name)()


@dataclass
class KeyInformation:
    key: ScpKey
    components: Mapping[int, int]

    @classmethod
    def parse(cls, data: bytes) -> "KeyInformation":
        return cls(
            ScpKey(data[:2]),
            dict(zip(data[2::2], data[3::2])),
        )


@dataclass
class CaIssuer:
    value: bytes
    key: ScpKey

    @classmethod
    def parse_list(cls, data: bytes) -> Sequence["CaIssuer"]:
        tlvs = Tlv.parse_list(data)
        return [
            cls(tlvs[i].value, ScpKey(tlvs[i + 1].value))
            for i in range(0, len(tlvs), 2)
        ]


def _int2asn1(value: int) -> bytes:
    bs = int2bytes(value)
    if bs[0] & 0x80:
        bs = b"\x00" + bs
    return Tlv(0x93, bs)


def _encrypt_ecb(key: bytes, data: bytes) -> bytes:
    encryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()  # nosec ECB
    ).encryptor()
    return encryptor.update(data) + encryptor.finalize()


class SecureDomainSession:
    """A session for managing SCP keys"""

    def __init__(self, connection: SmartCardConnection):
        self.protocol = SmartCardProtocol(connection)
        self.protocol.select(AID.SECURE_DOMAIN)
        logger.debug("SecureDomain session initialized")

    def authenticate(self, key_params: ScpKeyParams) -> None:
        self.protocol.init_scp(key_params)

    def get_data(self, tag: int, data: bytes = b"") -> bytes:
        return self.protocol.send_apdu(0, INS_GET_DATA, tag >> 8, tag & 0xFF, data)

    def get_key_information(self) -> Sequence[KeyInformation]:
        return [
            KeyInformation.parse(Tlv.unpack(0xC0, d))
            for d in Tlv.parse_list(self.get_data(0xE0))
        ]

    def get_card_recognition_data(self) -> bytes:
        return Tlv.unpack(0x73, self.get_data(0x66))

    def get_supported_ca_identifiers(self, kloc: bool = False) -> Sequence[CaIssuer]:
        """20-byte key identifier, key type, key version"""
        return CaIssuer.parse_list(self.get_data(0xFF33 if kloc else 0xFF34))

    def get_certificate_bundle(self, key: ScpKey) -> Sequence[x509.Certificate]:
        data = Tlv(0xA6, Tlv(0x83, key))
        return [
            x509.load_der_x509_certificate(cert)
            for cert in Tlv.parse_list(self.get_data(0xBF21, data))
        ]

    def reset(self) -> None:
        # Reset is done by blocking all available keys
        data = b"\0" * 8
        for key_info in self.get_key_information():
            key = key_info.key
            if key.kid == 0x01:
                key = ScpKey(0, 0)
                ins = INS_INITIALIZE_UPDATE
            elif key.kid in (0x02, 0x03):
                continue  # Skip these, will be deleted by 0x01
            elif key.kid in (0x11, 0x15):
                ins = INS_EXTERNAL_AUTHENTICATE
            elif key.kid == 0x13:
                ins = INS_INTERNAL_AUTHENTICATE
            else:  # 10, 20-2F
                ins = INS_PERFORM_SECURITY_OPERATION

            for _ in range(65):
                try:
                    self.protocol.send_apdu(0x80, ins, key.kvn, key.kid, data)
                except ApduError as e:
                    if e.sw in (
                        SW.AUTH_METHOD_BLOCKED,
                        SW.SECURITY_CONDITION_NOT_SATISFIED,
                    ):
                        break
                    elif e.sw == SW.INCORRECT_PARAMETERS:
                        continue
                    raise

    def store_data(self, data: bytes) -> None:
        self.protocol.send_apdu(0, INS_STORE_DATA, 0x90, 0, data)

    def store_certificate_bundle(
        self, key: ScpKey, certificates: Sequence[x509.Certificate]
    ) -> None:
        self.store_data(
            Tlv(0xA6, Tlv(0x83, key))
            + Tlv(
                0xBF21,
                b"".join(
                    c.public_bytes(serialization.Encoding.DER) for c in certificates
                ),
            )
        )

    def store_allow_list(self, key: ScpKey, serials: Sequence[int]) -> None:
        self.store_data(
            Tlv(0xA6, Tlv(0x83, key))
            + Tlv(0x70, b"".join(_int2asn1(s) for s in serials))
        )

    def store_issuer(self, key: ScpKey, issuer: bytes, klcc: bool = False) -> None:
        self.store_data(
            Tlv(
                0xA6,
                Tlv(0x80, b"\1" if klcc else b"\0")
                + Tlv(0x42, issuer)
                + Tlv(0x83, key),
            )
        )

    def delete_key(self, kid: int, kvn: int, delete_last: bool = False) -> None:
        if not kid and not kvn:
            raise ValueError("Must specify at least one of kid, kvn.")

        data = b""
        if kid:
            data += Tlv(0xD0, bytes([kid]))
        if kvn:
            data += Tlv(0xD2, bytes([kvn]))
        self.protocol.send_apdu(0x80, INS_DELETE, 0, int(delete_last), data)

    def generate_ec_key(
        self, key: ScpKey, curve: Curve = Curve.SECP256R1, replace_kvn: int = 0
    ) -> ec.EllipticCurvePublicKey:
        data = bytes([key.kvn]) + Tlv(KeyType.ECC_KEY_PARAMS, bytes([curve]))
        resp = self.protocol.send_apdu(
            0x80, INS_GENERATE_KEY, replace_kvn, key.kid, data
        )
        encoded_point = Tlv.unpack(KeyType.ECC_PUBLIC_KEY, resp)
        return ec.EllipticCurvePublicKey.from_encoded_point(curve._curve, encoded_point)

    def put_key(
        self,
        key: ScpKey,
        sk: Union[StaticKeys, ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
        replace_kvn: int = 0,
    ) -> None:
        processor = self.protocol._processor
        if not isinstance(processor, ScpProcessor):
            raise ValueError("Must be authenticated!")

        data = bytes([key.kvn])
        expected = data
        dek = processor._state._keys.key_dek
        p2 = key.kid
        if isinstance(sk, StaticKeys):
            if not sk.key_dek:
                raise ValueError("DEK must be set in static keys")
            p2 |= 0x80
            for k in sk:
                assert k  # nosec
                assert dek  # nosec
                kcv = _encrypt_ecb(k, _DEFAULT_KCV_IV)[:3]
                data += Tlv(KeyType.AES, _encrypt_ecb(dek, k)) + bytes([len(kcv)]) + kcv
                expected += kcv
        else:
            if isinstance(sk, ec.EllipticCurvePrivateKey):
                n = (sk.key_size + 7) // 8
                s = int2bytes(sk.private_numbers().private_value, n)
                assert dek  # nosec
                data += Tlv(KeyType.ECC_PRIVATE_KEY, _encrypt_ecb(dek, s))
            elif isinstance(sk, ec.EllipticCurvePublicKey):
                data += Tlv(
                    KeyType.ECC_PUBLIC_KEY,
                    sk.public_bytes(
                        serialization.Encoding.X962,
                        serialization.PublicFormat.UncompressedPoint,
                    ),
                )
            else:
                raise TypeError("Unsupported key type")
            data += Tlv(KeyType.ECC_KEY_PARAMS, bytes([Curve._from_key(sk)])) + b"\0"

        resp = self.protocol.send_apdu(0x80, INS_PUT_KEY, replace_kvn, p2, data)
        if resp != expected:
            raise BadResponseError("Incorrect key check value")
