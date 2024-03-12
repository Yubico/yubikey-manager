from enum import IntEnum


# https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf
# page 31
class BCD(IntEnum):
    zero = 0b00001
    one = 0b10000
    two = 0b01000
    three = 0b11001
    four = 0b00100
    five = 0b10101
    six = 0b01101
    seven = 0b11100
    eight = 0b00010
    nine = 0b10011
    ss = 0b11010
    fs = 0b10110
    es = 0b11111

    @classmethod
    def translate(cls, b: int) -> int:
        return {
            0: cls.zero,
            1: cls.one,
            2: cls.two,
            3: cls.three,
            4: cls.four,
            5: cls.five,
            6: cls.six,
            7: cls.seven,
            8: cls.eight,
            9: cls.nine,
        }[b]

    @classmethod
    def reverse_translate(cls, b: int) -> int:
        return {
            int(cls.zero): 0,
            int(cls.one): 1,
            int(cls.two): 2,
            int(cls.three): 3,
            int(cls.four): 4,
            int(cls.five): 5,
            int(cls.six): 6,
            int(cls.seven): 7,
            int(cls.eight): 8,
            int(cls.nine): 9,
        }[b]
