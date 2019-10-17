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

from .util import (APPLICATION, TRANSPORT, YUBIKEY, FORM_FACTOR, Tlv,
                   bytes2int, int2bytes)
from .driver import AbstractDriver, NotSupportedError
from enum import IntEnum, unique
import logging
import struct
import six


logger = logging.getLogger(__name__)


@unique
class TAG(IntEnum):
    USB_SUPPORTED = 0x01
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
    NFC_SUPPORTED = 0x0d
    NFC_ENABLED = 0x0e


@unique
class FLAGS(IntEnum):
    MODE_FLAG_EJECT = 0x80
    MODE_REMOTE_WAKEUP = 0x40


def _struct_pair(fmt):
    return (lambda v: struct.unpack(fmt, v)[0], lambda v: struct.pack(fmt, v))


_parse_config = {
    TAG.USB_SUPPORTED: (bytes2int, int2bytes),
    TAG.SERIAL: (bytes2int, int2bytes),
    TAG.USB_ENABLED: (bytes2int, int2bytes),
    TAG.FORMFACTOR: (lambda v: FORM_FACTOR.from_code(bytes2int(v)), int2bytes),
    TAG.VERSION: (lambda v: struct.unpack('>BBB', v),
                  lambda v: struct.pack('>BBB', *v)),
    TAG.AUTO_EJECT_TIMEOUT: _struct_pair('>H'),
    TAG.CHALRESP_TIMEOUT: _struct_pair('>B'),
    TAG.DEVICE_FLAGS: _struct_pair('>B'),
    TAG.APP_VERSIONS: (lambda v: v, lambda v: v),
    TAG.CONFIG_LOCK: (_struct_pair('>?')[0], lambda v: v),
    TAG.USE_LOCK_KEY: (None, lambda v: v),
    TAG.NFC_SUPPORTED: (bytes2int, int2bytes),
    TAG.NFC_ENABLED: (bytes2int, int2bytes)
}


def _set_value(data, tag, value):
    data[tag] = _parse_config[tag][1](value) if tag in _parse_config else value


def device_config(usb_enabled=None, nfc_enabled=None, flags=None,
                  auto_eject_timeout=None, chalresp_timeout=None,
                  config_lock=None):
    values = {}
    if config_lock is not None:
        if len(config_lock) != 16:
            raise ValueError('Config lock key must be 16 bytes')
        _set_value(values, TAG.CONFIG_LOCK, config_lock)
    if usb_enabled is not None:
        # Always add the unused CCID transport
        usb_enabled |= TRANSPORT.CCID
        _set_value(values, TAG.USB_ENABLED, usb_enabled)
    if nfc_enabled is not None:
        _set_value(values, TAG.NFC_ENABLED, nfc_enabled)
    if flags is not None:
        _set_value(values, TAG.DEVICE_FLAGS, flags)
    if auto_eject_timeout is not None:
        _set_value(values, TAG.AUTO_EJECT_TIMEOUT, auto_eject_timeout)
    if chalresp_timeout is not None:
        _set_value(values, TAG.CHALRESP_TIMEOUT, chalresp_timeout)
    return values


class DeviceConfig(object):

    def __init__(self, data=None):
        if not data:
            logger.debug('Config data empty/missing')
            self._tags = {}
            return

        c_len, data = six.indexbytes(data, 0), data[1:]
        data = data[:c_len]

        self._tags = Tlv.parse_dict(data)

    def _get(self, tag, default=None):
        if tag not in self._tags:
            return default
        val = self._tags[tag]
        return _parse_config[tag][0](val) if tag in _parse_config else val

    def _set(self, tag, value):
        _set_value(self._tags, tag, value)

    @property
    def serial(self):
        return self._get(TAG.SERIAL)

    @property
    def version(self):
        return self._get(TAG.VERSION)

    @property
    def form_factor(self):
        return self._get(TAG.FORMFACTOR, FORM_FACTOR.UNKNOWN)

    @property
    def usb_supported(self):
        return self._get(TAG.USB_SUPPORTED, 0)

    @property
    def usb_enabled(self):
        return self._get(TAG.USB_ENABLED, 0)

    @property
    def nfc_supported(self):
        return self._get(TAG.NFC_SUPPORTED, 0)

    @property
    def nfc_enabled(self):
        return self._get(TAG.NFC_ENABLED, 0)

    @property
    def app_versions(self):
        return self._get(TAG.APP_VERSIONS)

    @property
    def configuration_locked(self):
        return self._get(TAG.CONFIG_LOCK)

    @property
    def device_flags(self):
        return self._get(TAG.DEVICE_FLAGS, 0)


_NULL_DRIVER = AbstractDriver(0, 0)
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
        self._key_type = driver.key_type
        self.device_name = self._key_type.value
        self._descriptor = descriptor
        self._driver = driver

        try:
            logger.debug('Read config from device...')
            config = DeviceConfig(driver.read_config())
            logger.debug('Success!')
            if not config.version:  # This will succeed, 4.2 <= fw < 5
                config._set(TAG.VERSION, driver.read_version())
            if config.version >= (5, 0, 0):  # New capabilities
                self._can_write_config = True
            elif config.version == (4, 2, 4):  # Doesn't report correctly
                config._set(TAG.USB_SUPPORTED, 0x3f)
            if config.usb_supported ==\
                    (APPLICATION.OTP | APPLICATION.U2F | TRANSPORT.CCID):
                self.device_name = 'YubiKey Edge'
                config._set(TAG.USB_SUPPORTED,
                            config.usb_supported ^ TRANSPORT.CCID)
        except NotSupportedError as e:
            logger.debug('Failed to read config from device', exc_info=e)
            config = DeviceConfig()
            version = descriptor.version or driver.read_version()
            if version is not None:
                config._set(TAG.VERSION, version)

            serial = driver.read_serial()
            if serial is not None:
                config._set(TAG.SERIAL, serial)

            if self._key_type == YUBIKEY.SKY:
                logger.debug('Identified SKY 1')
                config._set(TAG.USB_SUPPORTED, APPLICATION.U2F)
            elif self._key_type == YUBIKEY.NEO:
                logger.debug('Identified NEO')
                if driver.transport == TRANSPORT.CCID:
                    logger.debug('CCID available, probe capabilities...')
                    usb_supported = driver.probe_capabilities()
                else:  # Assume base capabilities
                    logger.debug('CCID not available, guess capabilities')
                    usb_supported = _NEO_BASE_CAPABILITIES
                # NEO over 3.3.0 have U2F (which might be blocked by OS)
                if TRANSPORT.has(self.mode.transports, TRANSPORT.FIDO) \
                        or (version and version >= (3, 3, 0)):
                    usb_supported |= APPLICATION.U2F
                config._set(TAG.USB_SUPPORTED, usb_supported)
                config._set(TAG.NFC_SUPPORTED, usb_supported)
                config._set(TAG.NFC_ENABLED, usb_supported)
            elif self._key_type == YUBIKEY.YKP:
                logger.debug('YK Plus identified')
                config._set(TAG.USB_SUPPORTED,
                            APPLICATION.OTP | APPLICATION.U2F)
                self._can_mode_switch = False
            elif self._key_type == YUBIKEY.YKS:
                logger.debug('YK Standard identified')
                config._set(TAG.USB_SUPPORTED, APPLICATION.OTP)
                self._can_mode_switch = False

        # Fix usb_enabled
        if not config.usb_enabled:
            usb_enabled = config.usb_supported
            if not TRANSPORT.has(self.mode.transports, TRANSPORT.OTP):
                usb_enabled &= ~APPLICATION.OTP
            if not TRANSPORT.has(self.mode.transports, TRANSPORT.FIDO):
                usb_enabled &= ~(APPLICATION.U2F | APPLICATION.FIDO2)
            if not TRANSPORT.has(self.mode.transports, TRANSPORT.CCID):
                usb_enabled &= ~(
                    TRANSPORT.CCID |
                    APPLICATION.OATH |
                    APPLICATION.OPGP |
                    APPLICATION.PIV)
            config._set(TAG.USB_ENABLED, usb_enabled)

        # Workaround for invalid configurations.
        # Assume all form factors except USB_A_KEYCHAIN and
        # USB_C_KEYCHAIN >= 5.2.4 does not support NFC.
        if not ((config.form_factor is FORM_FACTOR.USB_A_KEYCHAIN)
                or (config.form_factor is FORM_FACTOR.USB_C_KEYCHAIN
                    and config.version >= (5, 2, 4))):
            config._set(TAG.NFC_SUPPORTED, 0)
            config._set(TAG.NFC_ENABLED, 0)

        self._config = config

        if self._key_type == YUBIKEY.SKY:
            self._can_mode_switch = False  # New capabilities
            if not APPLICATION.has(config.usb_supported, APPLICATION.FIDO2):
                logger.debug('SKY has no FIDO2, SKY 1')
                self.device_name = 'FIDO U2F Security Key'  # SKY 1
            if config.nfc_supported:
                self.device_name = 'Security Key NFC'
        elif self._key_type == YUBIKEY.YK4:
            if (5, 0, 0) <= self.version < (5, 1, 0) or \
                    self.version in [(5, 2, 0), (5, 2, 1), (5, 2, 2)]:
                self.device_name = 'YubiKey Preview'
            elif self.version >= (5, 1, 0):
                logger.debug('Identified YubiKey 5')
                self.device_name = 'YubiKey 5'
                if (config.form_factor == FORM_FACTOR.USB_A_KEYCHAIN
                        and not config.nfc_supported):
                    self.device_name += 'A'
                elif config.form_factor == FORM_FACTOR.USB_A_KEYCHAIN:
                    self.device_name += ' NFC'
                elif config.form_factor == FORM_FACTOR.USB_A_NANO:
                    self.device_name += ' Nano'
                elif config.form_factor == FORM_FACTOR.USB_C_KEYCHAIN:
                    self.device_name += 'C'
                    if config.nfc_supported:
                        self.device_name += ' NFC'
                elif config.form_factor == FORM_FACTOR.USB_C_NANO:
                    self.device_name += 'C Nano'
                elif config.form_factor == FORM_FACTOR.USB_C_LIGHTNING:
                    self.device_name += 'Ci'

            elif self.is_fips:
                self.device_name = 'YubiKey FIPS'

    @property
    def driver(self):
        return self._driver

    @property
    def config(self):
        return self._config

    @property
    def can_mode_switch(self):
        return self._can_mode_switch

    @property
    def can_write_config(self):
        return self._can_write_config

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
        return self._driver.mode

    @property
    def is_fips(self):
        return YubiKey.is_fips_version(self.version)

    @staticmethod
    def is_fips_version(version):
        return (4, 4, 0) <= version < (4, 5, 0)

    @mode.setter
    def mode(self, mode):
        if not self.has_mode(mode):
            raise ValueError('Mode not supported: %s' % mode)
        self.set_mode(mode)

    def write_config(self, values, reboot=False, lock_key=None):
        if not self._can_write_config:
            raise NotSupportedError()

        payload = b''.join(Tlv(k, v) for (k, v) in values.items())

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
        return '{0} {1[0]}.{1[1]}.{1[2]} {2} [{3.name}] ' \
            'serial: {4}' \
            .format(
                self.device_name,
                self.version,
                self.mode,
                self.transport,
                self.serial
            )
