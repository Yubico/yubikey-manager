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
from pathlib import Path


XDG_CONF = (
    Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser().resolve()
    / "ykman"
)
HOME_CONF = Path.home() / ".ykman"


def _get_conf_dir():
    """
    Gets the directory to be used for configuration.

    Two locations are supported for configuration. One following the XDG base directory
    layout, and one using a directory in $HOME.

    If either directory exists, use that, with preference to XDG.
    If neither exists, use XDG only if $XDG_CONFIG_HOME already exists.
    """

    for path in (XDG_CONF, HOME_CONF):
        if path.is_dir():
            return path
    return XDG_CONF if XDG_CONF.parent.is_dir() else HOME_CONF


class Settings(dict):
    def __init__(self, name):
        self.fname: Path = _get_conf_dir() / (name + ".json")
        if self.fname.is_file():
            with self.fname.open("r") as fd:
                self.update(json.load(fd))

    def __eq__(self, other):
        return other is not None and self.fname == other.fname

    def __ne__(self, other):
        return other is None or self.fname != other.fname

    def write(self):
        conf_dir = self.fname.parent
        if not conf_dir.is_dir():
            os.makedirs(conf_dir)
        with self.fname.open("w") as fd:
            json.dump(self, fd, indent=2)

    __hash__ = None
