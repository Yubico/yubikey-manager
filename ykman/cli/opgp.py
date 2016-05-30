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

from __future__ import absolute_import, print_function

from ykman.yubicommon.cli import CliCommand, Argument
from .util import confirm
from ..util import TRANSPORT
from ..opgp import OpgpController, KEY_SLOT, TOUCH_MODE
import getpass


KEY_NAMES = {
    'sig': KEY_SLOT.SIGN,
    'enc': KEY_SLOT.ENCRYPT,
    'aut': KEY_SLOT.AUTHENTICATE
}

MODE_NAMES = {
    'off': TOUCH_MODE.OFF,
    'on': TOUCH_MODE.ON,
    'fixed': TOUCH_MODE.ON_FIXED
}


def get_or_fail(data):
    def inner(key):
        if key in data:
            return data[key]
        raise ValueError('Invalid value: {}. Must be one of: {}'.format(
            key, ', '.join(data.keys())))
    return inner


def int_in_range(minval, maxval):
    def inner(val):
        intval = int(val)
        if minval <= intval <= maxval:
            return intval
        raise ValueError('Invalid value: {}. Must be in range {}-{}'.format(
            intval, minval, maxval))
    return inner


class OpgpCommand(CliCommand):
    """
    Manage YubiKey OpenPGP functions.

    Usage:
    ykman openpgp
    ykman openpgp reset [-f]
    ykman openpgp touch <key> [<policy>] [-f] [--admin-pin PIN]
    ykman openpgp set-pin-retries <pin_retries> <reset_code_retries>
                                  <admin_pin_retries> [--admin-pin PIN]

    <key> must be one of "sig", "enc", or "aut", and corresponds to one of the
    three available keys stored.
    <policy> must be one of "on", "off", or "fixed". Once "fixed" has been set
    on a key, it cannot be unset without performing a complete factory reset.
    <pin_retries>, <reset_code_retries> and <admin_pin_retries> should be given
    as three numerical values, in the range 1-255.

    Options:
        -h, --help         show this help message
        -f, --force        don't ask for confirmation for actions
        --admin-pin PIN    admin PIN to use. If omitted, you will be prompted
    """

    name = 'openpgp'
    transports = TRANSPORT.CCID

    action = Argument(('reset', 'touch', 'set-pin-retries'),
                      lambda x: x.replace('-', '_'), default='info')
    key = Argument('<key>', get_or_fail(KEY_NAMES))
    policy = Argument('<policy>', get_or_fail(MODE_NAMES))
    force = Argument('--force', bool)
    pin = Argument('--admin-pin')
    pw1_tries = Argument('<pin_retries>', int_in_range(1, 99))
    pw2_tries = Argument('<reset_code_retries>', int_in_range(1, 99))
    pw3_tries = Argument('<admin_pin_retries>', int_in_range(1, 99))

    def __call__(self, dev):
        controller = OpgpController(dev.driver)
        return getattr(self, '_{}_action'.format(self.action))(controller)

    def _confirm(self, message):
        if not self.force:
            confirm(message)

    def _info_action(self, controller):
        print('OpenPGP version: %d.%d.%d' % controller.version)

    def _reset_action(self, controller):
        self._confirm('WARNING! This will delete all stored OpenPGP keys and '
                      'data and restore factory settings?')
        print('Resetting OpenPGP data...')
        controller.reset()
        print('Success! All data has been cleared and default PINs are set.')
        print('PIN:       123456')
        print('Admin PIN: 12345678')

    def _touch_action(self, controller):
        old_policy = controller.get_touch(self.key)
        print('Current touch policy of {.name} key is {.name}.'.format(
            self.key, old_policy))
        if self.policy is None:
            return

        if old_policy == TOUCH_MODE.ON_FIXED:
            print('A FIXED policy cannot be changed!')
            return 1

        self._confirm('Set touch policy of {.name} key to {.name}?'.format(
            self.key, self.policy))
        if self.pin is None:
            self.pin = getpass.getpass('Enter Admin PIN: ')
        controller.set_touch(self.key, self.policy, self.pin.encode('utf8'))
        print('Touch policy successfully set.')

    def _set_pin_retries_action(self, controller):
        if controller.version <= (1, 0, 7) or \
                (4, 0, 0) <= controller.version < (4, 3, 0):
            raise ValueError('Changing the number of PIN retries is not '
                             'supported on this YubiKey.')
        self._confirm('Set PIN retry counters to: {} {} {}?'.format(
            self.pw1_tries, self.pw2_tries, self.pw3_tries))
        if self.pin is None:
            self.pin = getpass.getpass('Enter Admin PIN: ')
        controller.set_pin_retries(self.pw1_tries, self.pw2_tries,
                                   self.pw3_tries, self.pin.encode('utf8'))
        print('PIN retries successfully set.')
