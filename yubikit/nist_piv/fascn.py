from __future__ import annotations

from yubikit.nist_piv import BCD

from abc import ABC
from bitarray import bitarray
from io import StringIO


class FASCNBuilder(ABC):
    # Agency Code
    ac: list[int] = [BCD.zero] * 4

    # System Code
    sc: list[int] = [BCD.zero] * 4

    # Credential Number
    cn: list[int] = [BCD.zero] * 6

    # Credential Series
    cs: int = BCD.zero

    # Individual Credential Issue
    ici: int = BCD.zero

    #  Person Identifier
    pi: list[int] = [BCD.zero] * 10

    # Organizational Category
    oc: int = BCD.zero

    # Organizational Identifier
    oi: list[int] = [BCD.zero] * 4

    # Person/Organization Association Category
    poa: int = BCD.zero

    def agency_code(self, ac: list[int]) -> FASCNBuilder:
        self._assert_length(len(ac), 4)
        self.ac = list(map(BCD.translate, ac))
        return self

    def system_code(self, sc: list[int]) -> FASCNBuilder:
        self._assert_length(len(sc), 4)
        self.sc = list(map(BCD.translate, sc))
        return self

    def credential_number(self, cn: list[int]) -> FASCNBuilder:
        self._assert_length(len(cn), 6)
        self.cn = list(map(BCD.translate, cn))
        return self

    def credential_series(self, cs: int) -> FASCNBuilder:
        self.cs = BCD.translate(cs)
        return self

    def individual_credential_issue(self, ici: int) -> FASCNBuilder:
        self.ici = BCD.translate(ici)
        return self

    def person_identifier(self, pi: list[int]) -> FASCNBuilder:
        self._assert_length(len(pi), 10)
        self.pi = list(map(BCD.translate, pi))
        return self

    def organizational_category(self, oc: int) -> FASCNBuilder:
        self.oc = BCD.translate(oc)
        return self

    def organizational_identifier(self, oi: list[int]) -> FASCNBuilder:
        self._assert_length(len(oi), 4)
        self.oi = list(map(BCD.translate, oi))
        return self

    def organization_association_category(self, poa: int) -> FASCNBuilder:
        self.poa = BCD.translate(poa)
        return self

    def build(self) -> FASCN:
        return FASCN(self)

    def _assert_length(self, actual: int, expected: int):
        if actual != expected:
            raise RuntimeError(
                "expected {} characters, got {}".format(expected, actual)
            )


class FASCN(object):
    def __init__(self, builder: FASCNBuilder):
        self.ac = builder.ac
        self.sc = builder.sc
        self.cn = builder.cn
        self.cs = builder.cs
        self.ici = builder.ici
        self.pi = builder.pi
        self.oc = builder.oc
        self.oi = builder.oi
        self.poa = builder.poa

    def encode(self) -> bytes:
        b = bytearray()
        b.append(BCD.ss)
        b.extend(self.ac)
        b.append(BCD.fs)
        b.extend(self.sc)
        b.append(BCD.fs)
        b.extend(self.cn)
        b.append(BCD.fs)
        b.append(self.cs)
        b.append(BCD.fs)
        b.append(self.ici)
        b.append(BCD.fs)
        b.extend(self.pi)
        b.append(self.oc)
        b.extend(self.oi)
        b.append(self.poa)
        b.append(BCD.es)

        bs = bitarray(200)
        current_bit = 0
        for item in b:
            mask = 0x80
            tmp = item << 3
            for _ in range(0, 5):
                if (tmp & mask) == mask:
                    bs[current_bit] = True
                tmp = tmp << 1
                current_bit += 1

        bcd = bitarray(5)
        for marker in range(0, 195, 5):
            bcd ^= bs[marker : marker + 5]

        # write LRC error code
        bs[195:200] = bcd
        return self._convert_bitarray(bs)

    def _convert_bitarray(self, bs: bitarray):
        out = bytearray()
        current_bit = 0
        for _ in range(0, 25):
            current_byte = 0x00
            for j in range(0, 8):
                if bs[current_bit]:
                    current_byte = {
                        0: lambda x: x | 0x80,
                        1: lambda x: x | 0x40,
                        2: lambda x: x | 0x20,
                        3: lambda x: x | 0x10,
                        4: lambda x: x | 0x08,
                        5: lambda x: x | 0x04,
                        6: lambda x: x | 0x02,
                        7: lambda x: x | 0x01,
                    }[j](current_byte)
                current_bit += 1
            out.append(current_byte)
        return out

    @staticmethod
    def decode(b: bytes) -> FASCN:
        bs = bitarray(200)
        current_bit = 0
        for i in b:
            temp_byte = i
            mask = 0x80
            for _ in range(0, 8):
                if (temp_byte & mask) == mask:
                    bs[current_bit] = True
                temp_byte = temp_byte << 1
                current_bit += 1

        out = bytearray()
        for j in range(0, 200, 5):
            current_byte = 0x00
            tmp = bs[j : j + 5]
            current_bit = 0
            for k in range(0, 5):
                if tmp[current_bit]:
                    current_byte = {
                        0: lambda x: x | 0x10,
                        1: lambda x: x | 0x08,
                        2: lambda x: x | 0x04,
                        3: lambda x: x | 0x02,
                        4: lambda x: x | 0x01,
                    }[k](current_byte)
                current_bit += 1
            out.append(current_byte)

        fascn = FASCNBuilder().build()
        fascn.ac = list(map(int, out[1:5]))  # 4 bytes
        fascn.sc = list(map(int, out[6:10]))  # 4 bytes
        fascn.cn = list(map(int, out[11:17]))  # 6 bytes
        fascn.cs = int(out[18])  # 1 byte
        fascn.ici = int(out[20])  # 1 byte
        fascn.pi = list(map(int, out[22:32]))  # 10 bytes
        fascn.oc = int(out[32])  # 1 byte
        fascn.oi = list(map(int, out[33:37]))  # 5 bytes
        fascn.poa = int(out[37])  # 1 bytes
        return fascn

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FASCN):
            return self.encode() == other.encode()
        return False

    def __str__(self) -> str:
        out = StringIO()
        out.write("Agency Code: {}\n".format(list(map(BCD.reverse_translate, self.ac))))
        out.write("System Code: {}\n".format(list(map(BCD.reverse_translate, self.sc))))
        out.write(
            "Credential Number: {}\n".format(list(map(BCD.reverse_translate, self.cn)))
        )
        out.write("Credential Series: {}\n".format(BCD.reverse_translate(self.cs)))
        out.write(
            "Individual Credential Issue: {}\n".format(BCD.reverse_translate(self.ici))
        )
        out.write(
            "Person Identifier: {}\n".format(list(map(BCD.reverse_translate, self.pi)))
        )
        out.write(
            "Organizational Category: {}\n".format(BCD.reverse_translate(self.oc))
        )
        out.write(
            "Organizational Identifier: {}\n".format(
                list(map(BCD.reverse_translate, self.oi))
            )
        )
        out.write(
            "Person/Organization Association Category: {}\n".format(
                BCD.reverse_translate(self.poa)
            )
        )
        return out.getvalue()
