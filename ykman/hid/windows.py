# Original work Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modified work Copyright 2020 Yubico AB. All Rights Reserved.
# This file, with modifications, is licensed under the above Apache License.

from .base import OtpYubiKeyDevice, YUBICO_VID, USAGE_OTP
from yubikit.core.otp import OtpConnection

from ctypes import WinDLL  # type: ignore
from ctypes import wintypes, LibraryLoader
import ctypes
import platform
import logging
import re

logger = logging.getLogger(__name__)


# Load relevant DLLs
windll = LibraryLoader(WinDLL)
hid = windll.Hid
setupapi = windll.SetupAPI
kernel32 = windll.Kernel32


# Various structs that are used in the Windows APIs we call
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# On Windows, SetupAPI.h packs structures differently in 64bit and
# 32bit mode.  In 64-bit mode, the structures are packed on 8 byte
# boundaries, while in 32-bit mode, they are packed on 1 byte boundaries.
# This is important to get right for some API calls that fill out these
# structures.
if platform.architecture()[0] == "64bit":
    SETUPAPI_PACK = 8
elif platform.architecture()[0] == "32bit":
    SETUPAPI_PACK = 1
else:
    raise OSError(f"Unknown architecture: {platform.architecture()[0]}")


class DeviceInterfaceData(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", wintypes.DWORD),
        ("Reserved", ctypes.POINTER(ctypes.c_ulong)),
    ]
    _pack_ = SETUPAPI_PACK


class DeviceInterfaceDetailData(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("DevicePath", ctypes.c_byte * 1)]
    _pack_ = SETUPAPI_PACK


class HidAttributes(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_ulong),
        ("VendorID", ctypes.c_ushort),
        ("ProductID", ctypes.c_ushort),
        ("VersionNumber", ctypes.c_ushort),
    ]


class HidCapabilities(ctypes.Structure):
    _fields_ = [
        ("Usage", ctypes.c_ushort),
        ("UsagePage", ctypes.c_ushort),
        ("InputReportByteLength", ctypes.c_ushort),
        ("OutputReportByteLength", ctypes.c_ushort),
        ("FeatureReportByteLength", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort * 17),
        ("NotUsed", ctypes.c_ushort * 10),
    ]


# Various void* aliases for readability.
HDEVINFO = ctypes.c_void_p
HANDLE = ctypes.c_void_p
PHIDP_PREPARSED_DATA = ctypes.c_void_p  # pylint: disable=invalid-name

# This is a HANDLE.
INVALID_HANDLE_VALUE = 0xFFFFFFFF

# Status codes
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 0x03
NTSTATUS = ctypes.c_long
HIDP_STATUS_SUCCESS = 0x00110000

# CreateFile Flags
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

DIGCF_DEVICEINTERFACE = 0x10
DIGCF_PRESENT = 0x02

# Function signatures
hid.HidD_GetHidGuid.restype = None
hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(GUID)]
hid.HidD_GetAttributes.restype = wintypes.BOOLEAN
hid.HidD_GetAttributes.argtypes = [HANDLE, ctypes.POINTER(HidAttributes)]
hid.HidD_GetPreparsedData.restype = wintypes.BOOLEAN
hid.HidD_GetPreparsedData.argtypes = [HANDLE, ctypes.POINTER(PHIDP_PREPARSED_DATA)]
hid.HidD_FreePreparsedData.restype = wintypes.BOOLEAN
hid.HidD_FreePreparsedData.argtypes = [PHIDP_PREPARSED_DATA]
hid.HidD_GetProductString.restype = wintypes.BOOLEAN
hid.HidD_GetProductString.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_ulong]
hid.HidP_GetCaps.restype = NTSTATUS
hid.HidP_GetCaps.argtypes = [PHIDP_PREPARSED_DATA, ctypes.POINTER(HidCapabilities)]


hid.HidD_GetFeature.restype = wintypes.BOOL
hid.HidD_GetFeature.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_ulong]
hid.HidD_SetFeature.restype = wintypes.BOOL
hid.HidD_SetFeature.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_ulong]

setupapi.SetupDiGetClassDevsA.argtypes = [
    ctypes.POINTER(GUID),
    ctypes.c_char_p,
    wintypes.HWND,
    wintypes.DWORD,
]
setupapi.SetupDiGetClassDevsA.restype = HDEVINFO
setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
    HDEVINFO,
    ctypes.c_void_p,
    ctypes.POINTER(GUID),
    wintypes.DWORD,
    ctypes.POINTER(DeviceInterfaceData),
]
setupapi.SetupDiGetDeviceInterfaceDetailA.restype = wintypes.BOOL
setupapi.SetupDiGetDeviceInterfaceDetailA.argtypes = [
    HDEVINFO,
    ctypes.POINTER(DeviceInterfaceData),
    ctypes.POINTER(DeviceInterfaceDetailData),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [
    HDEVINFO,
]

kernel32.CreateFileA.restype = HANDLE
kernel32.CreateFileA.argtypes = [
    ctypes.c_char_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    HANDLE,
]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [HANDLE]


class WinHidOtpConnection(OtpConnection):
    def __init__(self, path):
        self.handle = kernel32.CreateFileA(
            path,
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if self.handle == INVALID_HANDLE_VALUE:
            raise ctypes.WinError()

    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def receive(self):
        buf = ctypes.create_string_buffer(9)
        result = hid.HidD_GetFeature(self.handle, buf, ctypes.sizeof(buf))
        if not result:
            raise ctypes.WinError()
        return buf.raw[1:]

    def send(self, data):
        buf = ctypes.create_string_buffer(b"\0" + bytes(data))
        result = hid.HidD_SetFeature(self.handle, buf, ctypes.sizeof(buf))
        if not result:
            raise ctypes.WinError()


def get_vid_pid(device):
    attributes = HidAttributes()
    result = hid.HidD_GetAttributes(device, ctypes.byref(attributes))
    if not result:
        raise ctypes.WinError()

    return attributes.VendorID, attributes.ProductID


def get_usage(device):
    preparsed_data = PHIDP_PREPARSED_DATA(0)
    ret = hid.HidD_GetPreparsedData(device, ctypes.byref(preparsed_data))
    if not ret:
        raise ctypes.WinError()

    try:
        caps = HidCapabilities()
        ret = hid.HidP_GetCaps(preparsed_data, ctypes.byref(caps))

        if ret != HIDP_STATUS_SUCCESS:
            raise ctypes.WinError()

        return caps.UsagePage, caps.Usage

    finally:
        hid.HidD_FreePreparsedData(preparsed_data)


VID_RE = re.compile(rb"\Wvid_%04x\W" % YUBICO_VID)
PID_RE = re.compile(rb"\Wpid_([a-z0-9]{4})\W")


def list_paths():
    hid_guid = GUID()
    hid.HidD_GetHidGuid(ctypes.byref(hid_guid))

    collection = setupapi.SetupDiGetClassDevsA(
        ctypes.byref(hid_guid), None, None, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
    )
    try:
        index = 0
        interface_info = DeviceInterfaceData()
        interface_info.cbSize = ctypes.sizeof(DeviceInterfaceData)

        paths = []
        while True:
            result = setupapi.SetupDiEnumDeviceInterfaces(
                collection,
                0,
                ctypes.byref(hid_guid),
                index,
                ctypes.byref(interface_info),
            )
            index += 1
            if not result:
                break

            detail_len = wintypes.DWORD()
            result = setupapi.SetupDiGetDeviceInterfaceDetailA(
                collection,
                ctypes.byref(interface_info),
                None,
                0,
                ctypes.byref(detail_len),
                None,
            )
            if result:
                raise ctypes.WinError()

            detail_len = detail_len.value
            if detail_len == 0:
                # skip this device, some kind of error
                continue

            buf = ctypes.create_string_buffer(detail_len)
            interface_detail = DeviceInterfaceDetailData.from_buffer(buf)
            interface_detail.cbSize = ctypes.sizeof(DeviceInterfaceDetailData)

            result = setupapi.SetupDiGetDeviceInterfaceDetailA(
                collection,
                ctypes.byref(interface_info),
                ctypes.byref(interface_detail),
                detail_len,
                None,
                None,
            )

            if not result:
                raise ctypes.WinError()

            path = ctypes.string_at(ctypes.addressof(interface_detail.DevicePath))
            if VID_RE.search(path):
                pid_match = PID_RE.search(path)
                if pid_match:
                    paths.append((int(pid_match.group(1), 16), path))
        return paths
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(collection)


def list_devices():
    devices = []
    for pid, path in list_paths():
        device = kernel32.CreateFileA(
            path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None,
        )
        if device == INVALID_HANDLE_VALUE:
            raise ctypes.WinError()
        try:
            usage = get_usage(device)
            if usage == USAGE_OTP:
                devices.append(OtpYubiKeyDevice(path, pid, WinHidOtpConnection))
        except Exception as e:
            logger.debug("Failed reading HID descriptor: %s", e)
            continue
        finally:
            kernel32.CloseHandle(device)
    return devices
