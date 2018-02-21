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

import logging
import ykman


LOG_LEVELS = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR,
              logging.CRITICAL]
LOG_LEVEL_NAMES = [logging.getLevelName(lvl) for lvl in LOG_LEVELS]


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


logging.disable(logging.CRITICAL * 2)
