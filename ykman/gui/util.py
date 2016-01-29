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


from collections import namedtuple


_SignalMapEntry = namedtuple('Entry', ['default_value', 'signal'])


class SignalMap(object):
    """
    A key value store that emits Signals when a value changes.
    """

    def __init__(self):
        self._entries = {}
        self._data = {}

    def __getitem__(self, key):
        try:
            return self._data[key]
        except KeyError:
            return self._entries[key].default_value

    def __setitem__(self, key, value):
        old_val = self[key]
        if old_val != value:
            self._data[key] = value
            signal = self._entries[key].signal
            if signal:
                signal.emit(value)

    def add_property(self, key, default_value, signal=None):
        self._entries[key] = _SignalMapEntry(default_value, signal)

    def clear(self, notify=True):
        """
        Set all properties to their default values.

        Use notify=False to prevent triggering singal emissions for changed
        values.
        """
        old_data, self._data = self._data, {}

        if notify:
            for key, old_val in old_data.items():
                entry = self._entries[key]
                if entry.signal and old_val != entry.default_value:
                    entry.signal.emit(entry.default_value)
