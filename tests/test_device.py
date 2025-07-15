from typing import cast

import pytest

from yubikit.core import TRANSPORT, YUBIKEY, Tlv
from yubikit.management import (
    CAPABILITY,
    FORM_FACTOR,
    DeviceConfig,
    DeviceInfo,
    Version,
)
from yubikit.support import get_name
from dataclasses import replace


DEFAULT_INFO = DeviceInfo(
    config=cast(DeviceConfig, None),
    serial=None,
    version=Version(5, 3, 0),
    form_factor=FORM_FACTOR.USB_A_KEYCHAIN,
    supported_capabilities={TRANSPORT.USB: CAPABILITY(0xFF)},  # type: ignore
    is_locked=False,
    is_fips=False,
)


def info(form_factor, **kwargs):
    return replace(DEFAULT_INFO, form_factor=form_factor, **kwargs)


def info_nfc(form_factor, **kwargs):
    return replace(
        DEFAULT_INFO,
        form_factor=form_factor,
        supported_capabilities={
            TRANSPORT.USB: CAPABILITY(0xFF),
            TRANSPORT.NFC: CAPABILITY(0xFF),
        },
        **kwargs,
    )


def test_yk5_formfactors():
    kt = YUBIKEY.YK4
    assert get_name(info(FORM_FACTOR.USB_A_KEYCHAIN), kt) == "YubiKey 5A"
    assert get_name(info_nfc(FORM_FACTOR.USB_A_KEYCHAIN), kt) == "YubiKey 5 NFC"
    assert get_name(info(FORM_FACTOR.USB_A_NANO), kt) == "YubiKey 5 Nano"
    assert get_name(info(FORM_FACTOR.USB_C_KEYCHAIN), kt) == "YubiKey 5C"
    assert get_name(info_nfc(FORM_FACTOR.USB_C_KEYCHAIN), kt) == "YubiKey 5C NFC"
    assert get_name(info(FORM_FACTOR.USB_C_NANO), kt) == "YubiKey 5C Nano"
    assert get_name(info(FORM_FACTOR.USB_C_LIGHTNING), kt) == "YubiKey 5Ci"
    assert (
        get_name(info(FORM_FACTOR.USB_A_BIO), kt)
        == "YubiKey Bio - Multi-protocol Edition"
    )
    assert (
        get_name(info(FORM_FACTOR.USB_C_BIO), kt)
        == "YubiKey C Bio - Multi-protocol Edition"
    )
    assert get_name(info(FORM_FACTOR.UNKNOWN), kt) == "YubiKey 5"
    assert get_name(info_nfc(FORM_FACTOR.UNKNOWN), kt) == "YubiKey 5 NFC"


def fido(device_info):
    device_info.supported_capabilities[TRANSPORT.USB] = (
        CAPABILITY.U2F | CAPABILITY.FIDO2
    )
    if TRANSPORT.NFC in device_info.supported_capabilities:
        device_info.supported_capabilities[TRANSPORT.NFC] = (
            CAPABILITY.U2F | CAPABILITY.FIDO2
        )
    return device_info


def test_yk5_fido():
    kt = YUBIKEY.YK4
    assert (
        get_name(fido(info(FORM_FACTOR.USB_A_BIO)), kt) == "YubiKey Bio - FIDO Edition"
    )
    assert (
        get_name(fido(info(FORM_FACTOR.USB_C_BIO)), kt)
        == "YubiKey C Bio - FIDO Edition"
    )


def fips(device_info):
    device_info.is_fips = True
    return device_info


def test_yk5_fips_formfactors():
    kt = YUBIKEY.YK4
    assert get_name(fips(info(FORM_FACTOR.USB_A_KEYCHAIN)), kt) == "YubiKey 5A FIPS"
    assert (
        get_name(fips(info_nfc(FORM_FACTOR.USB_A_KEYCHAIN)), kt) == "YubiKey 5 NFC FIPS"
    )
    assert get_name(fips(info(FORM_FACTOR.USB_A_NANO)), kt) == "YubiKey 5 Nano FIPS"
    assert get_name(fips(info(FORM_FACTOR.USB_C_KEYCHAIN)), kt) == "YubiKey 5C FIPS"
    assert (
        get_name(fips(info_nfc(FORM_FACTOR.USB_C_KEYCHAIN)), kt)
        == "YubiKey 5C NFC FIPS"
    )
    assert get_name(fips(info(FORM_FACTOR.USB_C_NANO)), kt) == "YubiKey 5C Nano FIPS"
    assert get_name(fips(info(FORM_FACTOR.USB_C_LIGHTNING)), kt) == "YubiKey 5Ci FIPS"
    assert get_name(fips(info(FORM_FACTOR.UNKNOWN)), kt) == "YubiKey 5 FIPS"
    assert get_name(fips(info_nfc(FORM_FACTOR.UNKNOWN)), kt) == "YubiKey 5 NFC FIPS"


def sky(device_info):
    device_info.is_sky = True
    return device_info


def test_sky_formfactors():
    kt = YUBIKEY.YK4
    assert get_name(sky(info(FORM_FACTOR.USB_A_KEYCHAIN)), kt) == "Security Key A"
    assert get_name(sky(info_nfc(FORM_FACTOR.USB_A_KEYCHAIN)), kt) == "Security Key NFC"
    assert get_name(sky(info(FORM_FACTOR.USB_A_NANO)), kt) == "Security Key Nano"
    assert get_name(sky(info(FORM_FACTOR.USB_C_KEYCHAIN)), kt) == "Security Key C"
    assert (
        get_name(sky(info_nfc(FORM_FACTOR.USB_C_KEYCHAIN)), kt) == "Security Key C NFC"
    )
    assert get_name(sky(info(FORM_FACTOR.USB_C_NANO)), kt) == "Security Key C Nano"
    assert get_name(sky(info(FORM_FACTOR.USB_C_LIGHTNING)), kt) == "Security Key Ci"
    assert get_name(sky(info(FORM_FACTOR.UNKNOWN)), kt) == "Security Key"
    assert get_name(sky(info_nfc(FORM_FACTOR.UNKNOWN)), kt) == "Security Key NFC"


def skyep(device_info):
    return replace(device_info, is_sky=True, serial=123456)


def test_sky_enterprise_formfactors():
    kt = YUBIKEY.YK4
    assert (
        get_name(skyep(info(FORM_FACTOR.USB_A_KEYCHAIN)), kt)
        == "Security Key A - Enterprise Edition"
    )
    assert (
        get_name(skyep(info_nfc(FORM_FACTOR.USB_A_KEYCHAIN)), kt)
        == "Security Key NFC - Enterprise Edition"
    )
    assert (
        get_name(skyep(info(FORM_FACTOR.USB_A_NANO)), kt)
        == "Security Key Nano - Enterprise Edition"
    )
    assert (
        get_name(skyep(info(FORM_FACTOR.USB_C_KEYCHAIN)), kt)
        == "Security Key C - Enterprise Edition"
    )
    assert (
        get_name(skyep(info_nfc(FORM_FACTOR.USB_C_KEYCHAIN)), kt)
        == "Security Key C NFC - Enterprise Edition"
    )
    assert (
        get_name(skyep(info(FORM_FACTOR.USB_C_NANO)), kt)
        == "Security Key C Nano - Enterprise Edition"
    )
    assert (
        get_name(skyep(info(FORM_FACTOR.USB_C_LIGHTNING)), kt)
        == "Security Key Ci - Enterprise Edition"
    )
    assert (
        get_name(skyep(info(FORM_FACTOR.UNKNOWN)), kt)
        == "Security Key - Enterprise Edition"
    )
    assert (
        get_name(skyep(info_nfc(FORM_FACTOR.UNKNOWN)), kt)
        == "Security Key NFC - Enterprise Edition"
    )


def epin(device_info):
    return replace(device_info, pin_complexity=True)


def test_enhanced_pin():
    kt = YUBIKEY.YK4
    assert (
        get_name(epin(info(FORM_FACTOR.USB_A_KEYCHAIN)), kt)
        == "YubiKey 5A - Enhanced PIN"
    )
    assert (
        get_name(epin(info_nfc(FORM_FACTOR.USB_A_KEYCHAIN)), kt)
        == "YubiKey 5 NFC - Enhanced PIN"
    )
    assert (
        get_name(epin(info_nfc(FORM_FACTOR.USB_C_KEYCHAIN)), kt)
        == "YubiKey 5C NFC - Enhanced PIN"
    )


DEVICE_INFO_TESTS = [
    (
        "YubiKey 5C NFC - Enhanced PIN",
        "0102033f0302033f0204020b885b04010305030507040602000007010f0801000d02033f0e02033f0a01000f010020030000002103000000100101110400000000120100130c3738434c5546583530303050140200001502000016010117010018020000",
    ),
    (
        "YubiKey 5C NFC FIPS",
        "0102033d0302033d020401ea505104018305030507040602000007010f0801000d02033d0e02033d0a01000f010020030000002103000000100101110400000000120100130c3738434c55465835303030501402001f1502001f16010117010018020000",
    ),
    (
        "YubiKey 5 Nano",
        "0102033f0302033e020401c234c404010205030507010602000007010f0801000a01000f010020030000002103000000100101110400000000120100130c3738434c55465835303030501402000015020008160100170100",
    ),
]


@pytest.mark.parametrize("expected_name, data", DEVICE_INFO_TESTS)
def test_device_info(expected_name, data):
    kt = YUBIKEY.YK4
    print(len(bytes.fromhex(data)))
    tlvs = Tlv.parse_dict(bytes.fromhex(data))
    info = DeviceInfo.parse_tlvs(tlvs, Version(5, 3, 0))
    assert get_name(info, kt) == expected_name
