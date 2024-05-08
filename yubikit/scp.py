from .core import Tlv
from .core.smartcard import (
    AID,
    SmartCardConnection,
    SmartCardProtocol,
)

from cryptography import x509
from dataclasses import dataclass
from typing import Mapping, Sequence, Union, Optional


import logging

logger = logging.getLogger(__name__)


INS_GET_DATA = 0xCA
INS_STORE_DATA = 0xE2


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


@dataclass
class KeyInformation:
    key: ScpKey
    componets: Mapping[int, int]

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


class ScpSession:
    """A session for managing SCP keys"""

    def __init__(self, connection: SmartCardConnection):
        self.protocol = SmartCardProtocol(connection)
        self.protocol.select(AID.SCP)
        logger.debug("SCP session initialized")

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
