# Copyright (c) 2020 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import fcntl
import glob
import logging
import struct
import sys
from typing import Set

from yubikit.core.otp import OtpConnection
from yubikit.logging import LOG_LEVEL

from .base import USAGE_OTP, YUBICO_VID, OtpYubiKeyDevice

# Don't typecheck this file on Windows
assert sys.platform != "win32"  # nosec

logger = logging.getLogger(__name__)

# usb_ioctl.h
USB_GET_REPORT = 0xC0094807
USB_SET_REPORT = 0xC0094806

# hidraw.h
HIDIOCGRAWINFO = 0x80084803
HIDIOCGRDESCSIZE = 0x80044801
HIDIOCGRDESC = 0x90044802


class HidrawConnection(OtpConnection):
    def __init__(self, path):
        self.handle = open(path, "wb")

    def close(self):
        self.handle.close()

    def receive(self):
        buf = bytearray(1 + 8)
        fcntl.ioctl(self.handle, USB_GET_REPORT, buf, True)
        data = buf[1:]
        logger.log(LOG_LEVEL.TRAFFIC, "RECV: %s", data.hex())
        return data

    def send(self, data):
        logger.log(LOG_LEVEL.TRAFFIC, "SEND: %s", data.hex())
        buf = bytearray([0])  # Prepend the report ID.
        buf.extend(data)
        fcntl.ioctl(self.handle, USB_SET_REPORT, buf, True)


def get_info(dev):
    buf = bytearray(4 + 2 + 2)
    fcntl.ioctl(dev, HIDIOCGRAWINFO, buf, True)
    return struct.unpack("<IHH", buf)


def get_descriptor(dev):
    buf = bytearray(4)
    fcntl.ioctl(dev, HIDIOCGRDESCSIZE, buf, True)
    size = struct.unpack("<I", buf)[0]
    buf += bytearray(size)
    fcntl.ioctl(dev, HIDIOCGRDESC, buf, True)
    return buf[4:]


def get_usage(dev):
    buf = get_descriptor(dev)
    usage, usage_page = (None, None)
    while buf:
        head, buf = buf[0], buf[1:]
        typ, size = 0xFC & head, 0x03 & head
        value, buf = buf[:size], buf[size:]
        if typ == 4:  # Usage page
            usage_page = struct.unpack("<I", value.ljust(4, b"\0"))[0]
            if usage is not None:
                return usage_page, usage
        elif typ == 8:  # Usage
            usage = struct.unpack("<I", value.ljust(4, b"\0"))[0]
            if usage_page is not None:
                return usage_page, usage


# Cache for continuously failing devices
_failed_cache: Set[str] = set()


def list_devices():
    devices = []
    for hidraw in glob.glob("/dev/hidraw*"):
        try:
            with open(hidraw, "rb") as f:
                bustype, vid, pid = get_info(f)
                if vid == YUBICO_VID and get_usage(f) == USAGE_OTP:
                    devices.append(OtpYubiKeyDevice(hidraw, pid, HidrawConnection))
            if hidraw in _failed_cache:
                _failed_cache.remove(hidraw)
        except Exception:
            if hidraw not in _failed_cache:
                logger.debug(
                    f"Couldn't read HID descriptor for {hidraw}", exc_info=True
                )
                _failed_cache.add(hidraw)
            continue

    return devices
