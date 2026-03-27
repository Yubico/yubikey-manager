from typing import Any

def read_info(reader_name: str) -> dict[str, Any]: ...
def get_name(
    version: tuple[int, int, int],
    form_factor: int,
    is_sky: bool,
    is_fips: bool,
    pin_complexity: bool,
    serial: int | None,
    usb_supported: int,
    has_nfc: bool,
) -> str: ...
