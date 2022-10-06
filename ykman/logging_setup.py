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

from ykman import __version__ as ykman_version
from ykman.util import get_windows_version
from ykman.logging import init_logging
from yubikit.logging import LOG_LEVEL
from datetime import datetime
import platform
import logging
import ctypes
import sys
import os


logger = logging.getLogger(__name__)


def log_sys_info(log):
    log(f"ykman: {ykman_version}")
    log(f"Python: {sys.version}")
    log(f"Platform: {sys.platform}")
    log(f"Arch: {platform.machine()}")
    if sys.platform == "win32":
        log(f"Windows version: {get_windows_version()}")
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    else:
        is_admin = os.getuid() == 0
    log(f"Running as admin: {is_admin}")
    log("System date: %s", datetime.today().strftime("%Y-%m-%d"))


def setup(log_level_name, log_file=None):
    log_level = LOG_LEVEL[log_level_name.upper()]
    init_logging(log_level, log_file=log_file)

    log_sys_info(logger.debug)
