# Copyright (c) 2022 Yubico AB
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

from yubikit.logging import LOG_LEVEL
import logging


logging.addLevelName(LOG_LEVEL.TRAFFIC, LOG_LEVEL.TRAFFIC.name)
logger = logging.getLogger(__name__)


def _print_box(*lines):
    w = max([len(ln) for ln in lines])
    bar = "#" * (w + 4)
    box = ["", bar]
    for ln in [""] + list(lines) + [""]:
        box.append(f"# {ln.ljust(w)} #")
    box.append(bar)
    return "\n".join(box)


TRAFFIC_WARNING = (
    "WARNING: All data sent to/from the YubiKey will be logged!",
    "This data may contain sensitive values, such as secret keys, PINs or passwords!",
)

DEBUG_WARNING = (
    "WARNING: Sensitive data may be logged!",
    "Some personally identifying information may be logged, such as usernames!",
)


def set_log_level(level: LOG_LEVEL):
    logging.getLogger().setLevel(level)

    logger.info(f"Logging at level: {level.name}")
    if level <= LOG_LEVEL.TRAFFIC:
        logger.warning(_print_box(*TRAFFIC_WARNING))
    elif level <= LOG_LEVEL.DEBUG:
        logger.warning(_print_box(*DEBUG_WARNING))


def init_logging(log_level: LOG_LEVEL, log_file=None):
    logging.basicConfig(
        force=log_file is None,  # Replace the default logger if logging to stderr
        datefmt="%H:%M:%S",
        filename=log_file,
        format="%(levelname)s %(asctime)s.%(msecs)d [%(name)s.%(funcName)s:%(lineno)d] "
        "%(message)s",
    )

    set_log_level(log_level)
