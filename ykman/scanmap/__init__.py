from enum import Enum
from . import us


class KEYBOARD_LAYOUT(Enum):
    US = 'US Keyboard Layout'


def get_scan_codes(data, keyboard_layout=KEYBOARD_LAYOUT.US):
    if keyboard_layout == KEYBOARD_LAYOUT.US:
        scancodes = us.scancodes
    else:
        raise ValueError('Keyboard layout not supported!')
    try:
        return bytes(bytearray(scancodes[c] for c in data))
    except KeyError:
        raise ValueError('Character not available in keyboard layout!')
