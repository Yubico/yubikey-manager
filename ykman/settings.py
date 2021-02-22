# Copyright (c) 2017 Yubico AB
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

import os
import json


CONFIG_DIR_CANDIDATES = (
    "./.ykman",
    "~/.ykman",
    "{}/ykman".format(os.environ.get("XDG_CONFIG_HOME", "~/.config")),
)


def _get_conf_dir():
    """
    gets directory to be used for configuration.

    It returns first candidate, for which path exists and is a directory. If none of
    candidates exists, it returns the last one, as this should be the preferred
    location to save the new configuration files.
    """
    for path in CONFIG_DIR_CANDIDATES:
        path = os.path.expanduser(os.path.abspath(path))
        if os.path.isdir(path):
            return path
    return os.path.expanduser(os.path.abspath(CONFIG_DIR_CANDIDATES[-1]))


class Settings(dict):
    def __init__(self, name):
        self.fname = os.path.join(_get_conf_dir(), name + ".json")
        if os.path.isfile(self.fname):
            with open(self.fname, "r") as f:
                self.update(json.load(f))

    def __eq__(self, other):
        return other is not None and self.fname == other.fname

    def __ne__(self, other):
        return other is not None or self.fname != other.fname

    def write(self):
        conf_dir = os.path.dirname(self.fname)
        if not os.path.isdir(conf_dir):
            os.makedirs(conf_dir)
        data = json.dumps(self, indent=2)
        with open(self.fname, "w") as f:
            f.write(data)

    __hash__ = None
