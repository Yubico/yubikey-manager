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
import logging


logger = logging.getLogger(__name__)


class ModeSwitchError(Exception):

    def __init__(self):
        super(ModeSwitchError, self).__init__('Failed to switch mode.')


class NotSupportedError(Exception):
    pass


class AbstractDriver(object):
    """Abstract driver class for communicating with a YubiKey"""

    transport = None

    def __init__(self, key_type, mode):
        self._key_type = key_type
        self._mode = mode

    @property
    def key_type(self):
        return self._key_type

    @property
    def mode(self):
        return self._mode

    def read_serial(self):
        """
        Attempt to read the serial number from the YubiKey, if available.

        This will only be called if read_config() fails to provide the serial.
        """
        return None

    def set_mode(self, mode_code):
        raise NotImplementedError()

    def read_version(self):
        """
        Attempt to read the firmware version from the YubiKey, if possible.

        If we cannot determine the firmware version with certainty this way,
        return None.
        """
        return None

    @property
    def is_in_fips_mode(self):
        raise NotImplementedError()

    def read_config(self):
        raise NotImplementedError()

    def write_config(self, data):
        raise NotImplementedError()

    def close(self):
        pass
