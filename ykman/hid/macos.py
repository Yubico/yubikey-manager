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

import ctypes
import ctypes.util
import logging

logger = logging.getLogger(__name__)

# Constants

HID_DEVICE_PROPERTY_VENDOR_ID = b"VendorID"
HID_DEVICE_PROPERTY_PRODUCT_ID = b"ProductID"
HID_DEVICE_PROPERTY_PRODUCT = b"Product"
HID_DEVICE_PROPERTY_PRIMARY_USAGE = b"PrimaryUsage"
HID_DEVICE_PROPERTY_PRIMARY_USAGE_PAGE = b"PrimaryUsagePage"
HID_DEVICE_PROPERTY_MAX_INPUT_REPORT_SIZE = b"MaxInputReportSize"
HID_DEVICE_PROPERTY_MAX_OUTPUT_REPORT_SIZE = b"MaxOutputReportSize"
HID_DEVICE_PROPERTY_REPORT_ID = b"ReportID"


# Declare C types
class _CFType(ctypes.Structure):
    pass


class _CFString(_CFType):
    pass


class _CFSet(_CFType):
    pass


class _IOHIDManager(_CFType):
    pass


class _IOHIDDevice(_CFType):
    pass


class _CFAllocator(_CFType):
    pass


CF_SET_REF = ctypes.POINTER(_CFSet)
CF_STRING_REF = ctypes.POINTER(_CFString)
CF_TYPE_REF = ctypes.POINTER(_CFType)
CF_ALLOCATOR_REF = ctypes.POINTER(_CFAllocator)
CF_DICTIONARY_REF = ctypes.c_void_p
CF_MUTABLE_DICTIONARY_REF = ctypes.c_void_p
CF_TYPE_ID = ctypes.c_ulong
CF_INDEX = ctypes.c_long
CF_TIME_INTERVAL = ctypes.c_double
IO_RETURN = ctypes.c_uint
IO_HID_REPORT_TYPE = ctypes.c_uint
IO_OPTION_BITS = ctypes.c_uint
IO_OBJECT_T = ctypes.c_uint
MACH_PORT_T = ctypes.c_uint
IO_SERVICE_T = IO_OBJECT_T
IO_REGISTRY_ENTRY_T = IO_OBJECT_T

IO_HID_MANAGER_REF = ctypes.POINTER(_IOHIDManager)
IO_HID_DEVICE_REF = ctypes.POINTER(_IOHIDDevice)

# Define C constants
K_CF_NUMBER_SINT32_TYPE = 3
K_CF_ALLOCATOR_DEFAULT = None

K_IO_MASTER_PORT_DEFAULT = 0
K_IO_HID_REPORT_TYPE_FEATURE = 2
K_IO_RETURN_SUCCESS = 0

# NOTE: find_library doesn't currently work on Big Sur, requiring the hardcoded paths
iokit = ctypes.cdll.LoadLibrary(
    ctypes.util.find_library("IOKit")
    or "/System/Library/Frameworks/IOKit.framework/IOKit"
)
cf = ctypes.cdll.LoadLibrary(
    ctypes.util.find_library("CoreFoundation")
    or "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
)


# Declare C function prototypes
cf.CFSetGetValues.restype = None
cf.CFSetGetValues.argtypes = [CF_SET_REF, ctypes.POINTER(ctypes.c_void_p)]
cf.CFStringCreateWithCString.restype = CF_STRING_REF
cf.CFStringCreateWithCString.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_uint32,
]
cf.CFGetTypeID.restype = CF_TYPE_ID
cf.CFGetTypeID.argtypes = [CF_TYPE_REF]
cf.CFNumberGetTypeID.restype = CF_TYPE_ID
cf.CFNumberGetValue.restype = ctypes.c_int
cf.CFRelease.restype = IO_RETURN
cf.CFRelease.argtypes = [CF_TYPE_REF]

iokit.IOObjectRelease.argtypes = [IO_OBJECT_T]

iokit.IOHIDManagerCreate.restype = IO_HID_MANAGER_REF
iokit.IOHIDManagerCreate.argtypes = [CF_ALLOCATOR_REF, IO_OPTION_BITS]
iokit.IOHIDManagerCopyDevices.restype = CF_SET_REF
iokit.IOHIDManagerCopyDevices.argtypes = [IO_HID_MANAGER_REF]
iokit.IOHIDManagerSetDeviceMatching.restype = None
iokit.IOHIDManagerSetDeviceMatching.argtypes = [IO_HID_MANAGER_REF, CF_TYPE_REF]

iokit.IORegistryEntryIDMatching.restype = CF_MUTABLE_DICTIONARY_REF
iokit.IORegistryEntryIDMatching.argtypes = [ctypes.c_uint64]
iokit.IORegistryEntryGetRegistryEntryID.restype = IO_RETURN
iokit.IORegistryEntryGetRegistryEntryID.argtypes = [
    IO_REGISTRY_ENTRY_T,
    ctypes.POINTER(ctypes.c_uint64),
]

iokit.IOHIDDeviceCreate.restype = IO_HID_DEVICE_REF
iokit.IOHIDDeviceCreate.argtypes = [CF_ALLOCATOR_REF, IO_SERVICE_T]
iokit.IOHIDDeviceClose.restype = IO_RETURN
iokit.IOHIDDeviceClose.argtypes = [IO_HID_DEVICE_REF, ctypes.c_uint32]
iokit.IOHIDDeviceGetProperty.restype = CF_TYPE_REF
iokit.IOHIDDeviceGetProperty.argtypes = [IO_HID_DEVICE_REF, CF_STRING_REF]
iokit.IOHIDDeviceSetReport.restype = IO_RETURN
iokit.IOHIDDeviceSetReport.argtypes = [
    IO_HID_DEVICE_REF,
    IO_HID_REPORT_TYPE,
    CF_INDEX,
    ctypes.c_void_p,
    CF_INDEX,
]
iokit.IOHIDDeviceGetReport.restype = IO_RETURN
iokit.IOHIDDeviceGetReport.argtypes = [
    IO_HID_DEVICE_REF,
    IO_HID_REPORT_TYPE,
    CF_INDEX,
    ctypes.c_void_p,
    ctypes.POINTER(CF_INDEX),
]

iokit.IOServiceGetMatchingService.restype = IO_SERVICE_T
iokit.IOServiceGetMatchingService.argtypes = [MACH_PORT_T, CF_DICTIONARY_REF]


class MacHidOtpConnection(OtpConnection):
    def __init__(self, path):
        # Resolve the path to device handle
        device_id = int(path)
        entry_id = ctypes.c_uint64(device_id)
        matching_dict = iokit.IORegistryEntryIDMatching(entry_id)
        device_entry = iokit.IOServiceGetMatchingService(
            K_IO_MASTER_PORT_DEFAULT, matching_dict
        )
        if not device_entry:
            raise OSError(
                f"Device ID {device_id} does not match any HID device on the system"
            )

        self.handle = iokit.IOHIDDeviceCreate(K_CF_ALLOCATOR_DEFAULT, device_entry)
        if not self.handle:
            raise OSError("Failed to obtain device handle from registry entry")
        iokit.IOObjectRelease(device_entry)

        # Open device
        result = iokit.IOHIDDeviceOpen(self.handle, 0)
        if result != K_IO_RETURN_SUCCESS:
            raise OSError(f"Failed to open device for communication: {result}")

    def close(self):
        if self.handle:
            iokit.IOHIDDeviceClose(self.handle, 0)
            self.handle = None

    def receive(self):
        buf = ctypes.create_string_buffer(8)
        report_len = CF_INDEX(ctypes.sizeof(buf))

        result = iokit.IOHIDDeviceGetReport(
            self.handle, K_IO_HID_REPORT_TYPE_FEATURE, 0, buf, ctypes.byref(report_len),
        )

        # Non-zero status indicates failure
        if result != K_IO_RETURN_SUCCESS:
            raise OSError(f"Failed to read report from device: {result}")

        return buf.raw[:]

    def send(self, data):
        buf = bytes(data)
        result = iokit.IOHIDDeviceSetReport(
            self.handle, K_IO_HID_REPORT_TYPE_FEATURE, 0, buf, len(buf),
        )

        # Non-zero status indicates failure
        if result != K_IO_RETURN_SUCCESS:
            raise OSError(f"Failed to write report to device: {result}")


def get_int_property(dev, key):
    """Reads int property from the HID device."""
    cf_key = cf.CFStringCreateWithCString(None, key, 0)
    type_ref = iokit.IOHIDDeviceGetProperty(dev, cf_key)
    cf.CFRelease(cf_key)
    if not type_ref:
        return None

    if cf.CFGetTypeID(type_ref) != cf.CFNumberGetTypeID():
        raise OSError(f"Expected number type, got {cf.CFGetTypeID(type_ref)}")

    out = ctypes.c_int32()
    ret = cf.CFNumberGetValue(type_ref, K_CF_NUMBER_SINT32_TYPE, ctypes.byref(out))
    if not ret:
        return None

    return out.value


def get_device_id(device_handle):
    """Obtains the unique IORegistry entry ID for the device.

    Args:
    device_handle: reference to the device

    Returns:
    A unique ID for the device, obtained from the IO Registry
    """
    # Obtain device entry ID from IO Registry
    io_service_obj = iokit.IOHIDDeviceGetService(device_handle)
    entry_id = ctypes.c_uint64()
    result = iokit.IORegistryEntryGetRegistryEntryID(
        io_service_obj, ctypes.byref(entry_id)
    )
    if result != K_IO_RETURN_SUCCESS:
        raise OSError(f"Failed to obtain IORegistry entry ID: {result}")

    return entry_id.value


def list_devices():
    # Init a HID manager
    hid_mgr = iokit.IOHIDManagerCreate(None, 0)
    if not hid_mgr:
        raise OSError("Unable to obtain HID manager reference")
    try:
        # Get devices from HID manager
        iokit.IOHIDManagerSetDeviceMatching(hid_mgr, None)
        device_set_ref = iokit.IOHIDManagerCopyDevices(hid_mgr)
        if not device_set_ref:
            raise OSError("Failed to obtain devices from HID manager")
        try:
            num = iokit.CFSetGetCount(device_set_ref)
            devices = (IO_HID_DEVICE_REF * num)()
            iokit.CFSetGetValues(device_set_ref, devices)

            # Retrieve and build descriptor dictionaries for each device
            devs = []
            for dev in devices:
                vid = get_int_property(dev, HID_DEVICE_PROPERTY_VENDOR_ID)
                if vid == YUBICO_VID:
                    pid = get_int_property(dev, HID_DEVICE_PROPERTY_PRODUCT_ID)
                    usage = (
                        get_int_property(dev, HID_DEVICE_PROPERTY_PRIMARY_USAGE_PAGE),
                        get_int_property(dev, HID_DEVICE_PROPERTY_PRIMARY_USAGE),
                    )
                    device_id = get_device_id(dev)
                    if usage == USAGE_OTP:
                        devs.append(
                            OtpYubiKeyDevice(str(device_id), pid, MacHidOtpConnection)
                        )
            return devs
        finally:
            cf.CFRelease(device_set_ref)
    finally:
        cf.CFRelease(hid_mgr)
