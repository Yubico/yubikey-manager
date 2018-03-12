from enum import Enum
from . import us


class KEYBOARD_LAYOUT(Enum):
    US = 'US Keyboard Layout'


def get_scan_codes(data, keyboard_layout=KEYBOARD_LAYOUT.US):
    if keyboard_layout == KEYBOARD_LAYOUT.US:
        return _get_us_scan_codes(data)
    else:
        raise ValueError('Keyboard layout not supported!')


def _get_us_scan_codes(data):
    scancodes = b''
    for char in data:
        if char in us.scancodes.keys():
            scancodes += us.scancodes[char]
        else:
            raise ValueError('Character not available in US keyboard layout!')
    return scancodes
