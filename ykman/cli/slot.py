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

import re
import sys
import argparse

from ..util import TRANSPORT

class SlotAction(argparse._SubParsersAction):

    def __call__(self, parser, args, values, option_string=None):
        print "Action called", args, values, option_string

        super(SlotAction, self).__call__(parser, args, values, option_string)


class SlotCommand(object):
    name = 'slot'
    help = 'configure aspects of the YubiKeys OTP mode slots'

    def __init__(self, parser):
        parser.add_argument('slot', type=int, nargs='?', choices=[1, 2],
                            help='which slot to act on')
        parser.add_argument('-f', '--force', action='store_true',
                            help='don\'t prompt for confirmation')

        #parser.add_argument('action', nargs='?', choices=['delete', 'swap'],
        #                    help='slot action')

        subparsers = parser.add_subparsers(help='slot action', action=SlotAction)
        info_parser = subparsers.add_parser(
            'info', help='show info about the slots')
        info_parser.set_defaults(action=self._info_action)
        delete_parser = subparsers.add_parser(
            'delete', help='deletes configuration in a slot')
        delete_parser.set_defaults(action=self._delete_action)
        swap_parser = subparsers.add_parser(
            'swap', help='swaps configurations between slots')
        swap_parser.set_defaults(action=None)
        static_parser = subparsers.add_parser(
            'static', help='programs a static password')
        static_parser.set_defaults(action=None)
        static_parser.add_argument('password', help='the password to set')

    def _delete_action(self, args, dev):
        if not args.force:
            print 'TODO: Ask for confirmation'
        print 'Deleting slot:', args.slot

    def run(self, args, dev):
        try:
            dev = dev.use_transport(TRANSPORT.OTP)
        except ValueError as e:
            print '%s Use the mode command to enable OTP.' % e.message
            return 1

        print args
        #action = getattr(self, '_%s_action' % args.action, self._info_action)

        #return action(args, dev)

    def _info_action(self, args, dev):
        print dev.device_name
        print "Slot 1:", dev.driver._slot1_valid and 'programmed' or 'empty'
        print "Slot 2:", dev.driver._slot2_valid and 'programmed' or 'empty'
