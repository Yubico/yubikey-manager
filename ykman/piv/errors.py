# Copyright (c) 2018 Yubico AB
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

from . import sw_util


class AuthenticationFailed(Exception):
    def __init__(self, message, sw, applet_version):
        super().__init__(message)
        self.tries_left = (
            sw_util.tries_left(sw, applet_version)
            if sw_util.is_verify_fail(sw, applet_version)
            else None)


class AuthenticationBlocked(AuthenticationFailed):
    def __init__(self, message, sw):
        # Dummy applet_version since sw will always be "authentication blocked"
        super().__init__(message, sw, ())


class BadFormat(Exception):
    def __init__(self, message, bad_value):
        super().__init__(message)
        self.bad_value = bad_value


class UnsupportedAlgorithm(Exception):
    def __init__(self, message, algorithm_id=None, key=None, ):
        super().__init__(message)
        if algorithm_id is None and key is None:
            raise ValueError(
                'At least one of algorithm_id and key must be given.')

        self.algorithm_id = algorithm_id
        self.key = key


class UnknownPinPolicy(Exception):
    def __init__(self, policy_name):
        super().__init__(
            'Unsupported pin policy: %s' % policy_name)
        self.policy_name = policy_name


class UnknownTouchPolicy(Exception):
    def __init__(self, policy_name):
        super().__init__(
            'Unsupported touch policy: %s' % policy_name)
        self.policy_name = policy_name


class WrongPin(AuthenticationFailed):
    def __init__(self, sw, applet_version):
        super().__init__('Incorrect PIN', sw, applet_version)


class WrongPuk(AuthenticationFailed):
    def __init__(self, sw, applet_version):
        super().__init__('Incorrect PUK', sw, applet_version)
