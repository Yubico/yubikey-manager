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

from ykman.yubicommon.cli import CliCommand, Argument
from .util import confirm
from ..util import TRANSPORT


class SlotCommand(CliCommand):
    """
    Manage YubiKey OTP slots.

    Usage:
    ykman slot
    ykman slot swap [-f]
    ykman slot (1 | 2) delete [-f]
    ykman slot (1 | 2) static <password> [-f] [--no-enter]

    Options:
        -h, --help      show this help message
        -f, --force     don't ask for confirmation for actions
        --no-enter      don't trigger the Enter key after the password
    """

    name = 'slot'
    transports = TRANSPORT.OTP

    slot = Argument(('1', '2'), int)
    action = Argument(('static', 'swap', 'delete'), default='info')
    force = Argument('--force', bool)
    no_enter = Argument('--no-enter', bool)
    static_password = Argument('<password>')

    def __call__(self, dev):
        return getattr(self, '_{}_action'.format(self.action))(dev)

    def _info_action(self, dev):
        print dev.device_name
        print "Slot 1:", dev.driver._slot1_valid and 'programmed' or 'empty'
        print "Slot 2:", dev.driver._slot2_valid and 'programmed' or 'empty'

    def _swap_action(self, dev):
        if not self.force and not confirm('Swap slots of YubiKey?'):
            return 1
        print 'Swapping slots...'
        dev.driver.swap_slots()
        print 'Success!'

    def _delete_action(self, dev):
        if not self.force and \
                not confirm('Delete slot %d of YubiKey?' % self.slot):
            return 1
        print 'Deleting slot: %d...' % self.slot
        dev.driver.zap_slot(self.slot)
        print 'Success!'

    def _static_action(self, dev):
        if not self.force and \
                not confirm('Program a static password in slot %d?' % self.slot):
            return 1
        print "Setting static password in slot %d..." % self.slot
        dev.driver.program_static(self.slot, self.static_password,
                                  not self.no_enter)
        print 'Success!'
