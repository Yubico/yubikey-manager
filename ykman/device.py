# Copyright (c) 2015 Yubico AB
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

from __future__ import absolute_import

from .util import (APPLICATION, TRANSPORT, YUBIKEY, FORM_FACTOR, Mode, Tlv,
                   parse_tlvs, bytes2int, int2bytes)
from .driver import AbstractDriver
from enum import IntEnum, unique
import logging
import struct
import six


logger = logging.getLogger(__name__)


@unique
class TAG(IntEnum):
    USB_CAPA = 0x01
    SERIAL = 0x02
    USB_ENABLED = 0x03
    FORMFACTOR = 0x04
    VERSION = 0x05
    AUTO_EJECT_TIMEOUT = 0x06
    CHALRESP_TIMEOUT = 0x07
    DEVICE_FLAGS = 0x08
    APP_VERSIONS = 0x09
    CONFIG_LOCK = 0x0a
    USE_LOCK_KEY = 0x0b
    REBOOT = 0x0c
    NFC_CAPA = 0x0d
    NFC_ENABLED = 0x0e


def device_config(usb_enabled=None, nfc_enabled=None, flags=None,
                  auto_eject_timeout=None, chalresp_timeout=None,
                  config_lock=None):
    payload = b''
    if config_lock is not None:
        if len(payload) != 16:
            raise ValueError('Config lock key must be 16 bytes')
        payload += Tlv(TAG.CONFIG_LOCK, payload)
    if usb_enabled is not None:
        payload += Tlv(TAG.USB_ENABLED, int2bytes(usb_enabled))
    if nfc_enabled is not None:
        payload += Tlv(TAG.NFC_ENABLED, int2bytes(nfc_enabled))
    if flags is not None:
        payload += Tlv(TAG.DEVICE_FLAGS, struct.pack('>B', flags))
    if auto_eject_timeout is not None:
        payload += Tlv(TAG.AUTO_EJECT_TIMEOUT,
                       struct.pack('>H', auto_eject_timeout))
    if chalresp_timeout is not None:
        payload += Tlv(TAG.CHALRESP_TIMEOUT,
                       struct.pack('>B', chalresp_timeout))
    return payload


class DeviceConfig(object):

    def __init__(self, data=None):
        self.serial = None
        self.version = None
        self.form_factor = FORM_FACTOR.UNKNOWN
        self.usb_supported = 0
        self.usb_enabled = 0
        self.nfc_supported = 0
        self.nfc_enabled = 0
        self.app_versions = None
        self.configuration_locked = False
        self.device_flags = 0

        if not data:
            logger.debug('Config data empty/missing')
            return

        c_len, data = six.indexbytes(data, 0), data[1:]
        data = data[:c_len]

        for tlv in parse_tlvs(data):
            if TAG.SERIAL == tlv.tag:
                self.serial = bytes2int(tlv.value)
                logger.debug('Config serial: %d', self.serial)
            elif TAG.VERSION == tlv.tag:
                self.version = tuple(c for c in six.iterbytes(tlv.value))
                logger.debug('Config version: %r', self.version)
            elif TAG.FORMFACTOR == tlv.tag:
                self.form_factor = FORM_FACTOR.from_code(bytes2int(tlv.value))
                logger.debug('Config form factor: %s', self.form_factor)
            elif TAG.DEVICE_FLAGS == tlv.tag:
                self.device_flags = bytes2int(tlv.value)
                logger.debug('Config device flags: %s', bin(self.device_flags))
            elif TAG.APP_VERSIONS == tlv.tag:
                self.app_versions = tlv.value
                logger.debug('Config app versions: %s', self.app_versions)
            elif TAG.CONFIG_LOCK == tlv.tag:
                self.configuration_locked = bool(six.indexbytes(tlv.value, 0))
                logger.debug('Config locked: %s', self.configuration_locked)
            elif TAG.USB_CAPA == tlv.tag:
                self.usb_supported = bytes2int(tlv.value)
                logger.debug('Config usb capabilities: %s',
                             bin(self.usb_supported))
            elif TAG.USB_ENABLED == tlv.tag:
                self.usb_enabled = bytes2int(tlv.value)
                logger.debug('Config usb enabled: %s',
                             bin(self.usb_enabled))
            elif TAG.NFC_CAPA == tlv.tag:
                self.nfc_supported = bytes2int(tlv.value)
                logger.debug('Config nfc capabilities: %s',
                             bin(self.nfc_supported))
            elif TAG.NFC_ENABLED == tlv.tag:
                self.nfc_enabled = bytes2int(tlv.value)
                logger.debug('Config nfc enabled: %s',
                             bin(self.nfc_enabled))


_NULL_DRIVER = AbstractDriver(0)
_NEO_BASE_CAPABILITIES = TRANSPORT.CCID | APPLICATION.OTP | APPLICATION.OATH \
    | APPLICATION.OPGP | APPLICATION.PIV


class YubiKey(object):
    """
    YubiKey device handle
    """
    device_name = 'YubiKey'
    _can_mode_switch = True
    _can_write_config = False

    def __init__(self, descriptor, driver):
        self._key_type = driver.pid.get_type()
        self.device_name = self._key_type.value
        self._descriptor = descriptor
        self._driver = driver

        try:
            logger.debug('Read config from device...')
            config = DeviceConfig(driver.read_config())
            logger.debug('Success!')
            self._version_certain = True
            if not config.version:
                config.version = driver.guess_version()
            if config.version >= (5, 0, 0):  # New capabilities
                self._can_write_config = True
            elif config.version == (4, 2, 4):  # Doesn't report correctly
                config.usb_supported = 0x3f
            if config.usb_supported ==\
                    (APPLICATION.OTP | APPLICATION.U2F | TRANSPORT.CCID):
                self.device_name = 'YubiKey Edge'
                config.usb_supported ^= TRANSPORT.CCID
        except Exception:  # TODO Proper exception
            logger.debug('Failed to read config from device')
            config = DeviceConfig()
            config.version = descriptor.version
            if config.version is not None:
                self._version_certain = True
            else:
                config.version = driver.guess_version()
                self._version_certain = self._key_type != YUBIKEY.NEO

            try:
                config.serial = driver.read_serial()
            except Exception:
                config.serial = None

            if self._key_type == YUBIKEY.SKY:
                logger.debug('Identified SKY 1')
                config.usb_supported = APPLICATION.U2F
            elif self._key_type == YUBIKEY.NEO:
                logger.debug('Identified NEO')
                if driver.transport == TRANSPORT.CCID:
                    logger.debug('CCID available, probe capabilities...')
                    config.usb_supported = driver.probe_capabilities()
                else:  # Assume base capabilities
                    logger.debug('CCID not available, guess capabilities')
                    config.usb_supported = _NEO_BASE_CAPABILITIES
                    if TRANSPORT.has(self.mode.transports, TRANSPORT.FIDO) \
                            or config.version >= (3, 3, 0):
                        config.usb_supported |= APPLICATION.U2F
                config.nfc_supported = config.usb_supported
                config.nfc_enabled = config.nfc_supported
            elif self._key_type == YUBIKEY.YKP:
                logger.debug('YK Plus identified')
                config.usb_supported = APPLICATION.OTP | APPLICATION.U2F
                self._can_mode_switch = False
            elif self._key_type == YUBIKEY.YKS:
                logger.debug('YK Standard identified')
                config.usb_supported = APPLICATION.OTP
                self._can_mode_switch = False

        if not config.usb_enabled:
            # This is wrong, but gets fixed below
            config.usb_enabled = config.usb_supported

        # Fix USB enabled
        if not TRANSPORT.has(self.mode.transports, TRANSPORT.OTP):
            config.usb_enabled &= ~APPLICATION.OTP
        if not TRANSPORT.has(self.mode.transports, TRANSPORT.FIDO):
            config.usb_enabled &= ~(APPLICATION.U2F | APPLICATION.FIDO2)
        if not TRANSPORT.has(self.mode.transports, TRANSPORT.CCID):
            config.usb_enabled &= ~(TRANSPORT.CCID | APPLICATION.OATH |
                                    APPLICATION.OPGP | APPLICATION.PIV)

        self._config = config

        if self._key_type == YUBIKEY.SKY:
            self._can_mode_switch = False  # New capabilities
            if not APPLICATION.has(config.usb_supported, APPLICATION.FIDO2):
                logger.debug('SKY has no FIDO2, SKY 1')
                self.device_name = 'FIDO U2F Security Key'  # SKY 1
        elif self._key_type == YUBIKEY.YK4:
            if self.version >= (5, 0, 0):
                self.device_name = 'YubiKey Preview'

    @property
    def driver(self):
        return self._driver

    @property
    def config(self):
        return self._config

    @property
    def version_certain(self):
        return self._version_certain

    @property
    def can_mode_switch(self):
        return self._can_mode_switch

    @property
    def version(self):
        return self._config.version

    @property
    def serial(self):
        return self._config.serial

    @property
    def form_factor(self):
        return self._config.form_factor

    @property
    def key_type(self):
        return self._key_type

    @property
    def transport(self):
        return self._driver.transport

    @property
    def mode(self):
        return Mode.from_pid(self._driver.pid)

    @mode.setter
    def mode(self, mode):
        if not self.has_mode(mode):
            raise ValueError('Mode not supported: %s' % mode)
        self.set_mode(mode)

    def write_config(self, payload, reboot=False, lock_key=None):
        if not self._can_write_config:
            raise NotImplementedError()

        if lock_key:
            payload += Tlv(TAG.USE_LOCK_KEY, lock_key)
        elif self.config.configuration_locked:
            raise ValueError('Configuration locked!')
        if reboot:
            payload += Tlv(TAG.REBOOT)
        payload = struct.pack('>B', len(payload)) + payload
        self._driver.write_config(payload)
        if reboot:
            self.close()
        else:
            self.config = DeviceConfig(self._driver.read_config())

    def has_mode(self, mode):
        return self.mode == mode or \
            (self.can_mode_switch and
             TRANSPORT.has(self._config.usb_supported, mode.transports))

    def set_mode(self, mode, cr_timeout=None, autoeject_time=None):
        flags = 0

        # If autoeject_time is set, then set the touch eject flag.
        if autoeject_time is not None:
            flags |= 0x80
        else:
            autoeject_time = 0

        # NEO < 3.3.1 (?) should always set 82 instead of 2.
        if self.version <= (3, 3, 1) and mode.code == 2:
            flags = 0x80
        if not self._can_write_config:
            self._driver.set_mode(flags | mode.code, cr_timeout or 0,
                                  autoeject_time)
        else:
            self.write_config(device_config(
                usb_enabled=self.config.usb_supported & (
                    ((APPLICATION.U2F | APPLICATION.FIDO2) *
                     mode.has_transport(TRANSPORT.FIDO)) |
                    ((APPLICATION.OATH | APPLICATION.OPGP | APPLICATION.PIV) *
                     mode.has_transport(TRANSPORT.CCID)) |
                    ((APPLICATION.OTP) * mode.has_transport(TRANSPORT.OTP))
                ),
                flags=flags,
                chalresp_timeout=cr_timeout,
                auto_eject_timeout=autoeject_time
            ), reboot=True)

    def use_transport(self, transport):
        if self.transport == transport:
            return self
        if not TRANSPORT.has(self.mode.transports, transport):
            raise ValueError('%s transport not enabled!' % transport)

        del self._driver
        self._driver = _NULL_DRIVER

        return self._descriptor.open_device(transport, self.serial)

    def close(self):
        self._driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __str__(self):
        return '{0} {1[0]}.{1[1]}.{1[2]} {2} [{3.name}]' \
            'serial: {4}' \
            .format(
                self.device_name,
                self.version,
                self.mode,
                self.transport,
                self.serial
            )
