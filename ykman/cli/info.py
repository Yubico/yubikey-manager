# Copyright (c) 2016 Yubico AB
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

import sys
from ykman import __version__
from ..util import CAPABILITY, TRANSPORT
from ..driver_otp import libversion as ykpers_version
from ..driver_u2f import libversion as u2fhost_version


class InfoCommand(object):
    name = 'info'
    help = 'display information about the attached YubiKey'

    def __init__(self, parser):
        pass

    def run(self, args, dev):
        print '{} (YubiKey Manager CLI) {}'.format(sys.argv[0], __version__)
        print 'Libraries: libykpers {}, libu2f-host {}'.format(
            ykpers_version, u2fhost_version)
        print

        print 'Device name:', dev.device_name
        print 'Serial number:', dev.serial or 'Not set or unreadable'
        print 'Enabled transport(s):', dev.mode
        print

        print 'Device capabilities:'
        for c in CAPABILITY:
            if c & dev.capabilities:
                if c & dev.enabled:
                    status = 'Enabled'
                else:
                    status = 'Disabled'
            else:
                status = 'Not available'

            print '    {0.name}:\t{1}'.format(c, status)
