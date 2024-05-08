from .core import Tlv
from .core.smartcard import (
    AID,
    SmartCardConnection,
    SmartCardProtocol,
)
from .core.scp import Key

from cryptography import x509
from dataclasses import dataclass
from typing import Mapping, Sequence


import logging

logger = logging.getLogger(__name__)


INS_GET_DATA = 0xCA
INS_STORE_DATA = 0xE2


@dataclass
class KeyInformation:
    key: Key
    componets: Mapping[int, int]

    @classmethod
    def parse(cls, data: bytes) -> "KeyInformation":
        return cls(
            Key(data[:2]),
            dict(zip(data[2::2], data[3::2])),
        )


@dataclass
class CaIssuer:
    value: bytes
    key: Key

    @classmethod
    def parse_list(cls, data: bytes) -> Sequence["CaIssuer"]:
        tlvs = Tlv.parse_list(data)
        return [
            cls(tlvs[i].value, Key(tlvs[i + 1].value)) for i in range(0, len(tlvs), 2)
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

    def get_certificate_bundle(self, key: Key) -> Sequence[x509.Certificate]:
        data = Tlv(0xA6, Tlv(0x83, key))
        return [
            x509.load_der_x509_certificate(cert)
            for cert in Tlv.parse_list(self.get_data(0xBF21, data))
        ]
