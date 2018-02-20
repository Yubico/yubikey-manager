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

from __future__ import absolute_import

import inspect
import logging
import os
import subprocess
import ykman


LOG_LEVELS = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR,
              logging.CRITICAL]
LOG_LEVEL_NAMES = [logging.getLevelName(lvl) for lvl in LOG_LEVELS]

ykman_dir = os.path.dirname(dict(inspect.getmembers(ykman))['__file__'])
git_version = None

try:
    git_describe_proc = subprocess.Popen(
        ['git', '-C', ykman_dir,
         'describe', '--tags', '--always', '--dirty=-DIRTY'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    git_describe_proc.wait()
    if git_describe_proc.returncode == 0:
        git_version = git_describe_proc.stdout.read().decode('utf-8').strip()
except Exception:
    pass


def setup(log_level_name, log_file=None):
    log_level_value = next(
        (lvl for lvl in LOG_LEVELS
         if logging.getLevelName(lvl) == log_level_name),
        None
    )

    if log_level_value is None:
        raise ValueError('Unknown log level: ' + log_level_name)

    logging.disable(logging.NOTSET)
    logging.basicConfig(
        datefmt='%Y-%m-%dT%H:%M:%S%z',
        filename=log_file,
        format='%(asctime)s %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s',  # noqa: E501
        level=log_level_value
    )

    logger = logging.getLogger(__name__)
    logger.info('Initialized logging for %s version: %s',
                ykman.__name__, ykman.__version__)
    logger.debug('Git version: %s', git_version)


logging.disable(logging.CRITICAL * 2)
