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
from ..util import TRANSPORT


class SlotCommand(CliCommand):
    """
    Manage YubiKey OTP slots.

    Usage:
    ykman slot
    ykman slot swap [-f]
    ykman slot (1 | 2) delete [-f]
    ykman slot (1 | 2) static <password> [-f]

    Options:
        -h, --help      show this help message
        -f, --force     don't ask for confirmation for actions
    """

    name = 'slot'

    slot = Argument(('1', '2'), int)
    action = Argument(('static', 'swap', 'delete'), default='info')
    force = Argument('--force', bool)
    static_password = Argument('<password>')

    def __call__(self, dev):
        try:
            dev = dev.use_transport(TRANSPORT.OTP)
        except ValueError as e:
            print '%s Use the mode command to enable OTP.' % e.message
            return 1

        return getattr(self, '_{}_action'.format(self.action))(dev)

    def _info_action(self, dev):
        print dev.device_name
        print "Slot 1:", dev.driver._slot1_valid and 'programmed' or 'empty'
        print "Slot 2:", dev.driver._slot2_valid and 'programmed' or 'empty'

    def _swap_action(self, dev):
        print "Swap slots"

    def _delete_action(self, dev):
        if not self.force:
            print 'TODO: Ask for confirmation'
        print 'Deleting slot:', self.slot

    def _static_action(self, dev):
        print "Set static password in slot %d: %s" % (
            self.slot, self.static_password)
