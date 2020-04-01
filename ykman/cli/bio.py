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

from __future__ import absolute_import

from .util import click_postpone_execution
from ..bio import BioController
from ..util import TRANSPORT
from ..descriptor import get_descriptors
from time import sleep
import logging
import click


logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
@click_postpone_execution
def bio(ctx):
    """
    Internal YubiKey BIO commands.

    Examples:

    \b
      Dump logs from the YubiKey to a CSV file.
      $ ykman bio dump-logs

    \b
      Clear all stored logs from the device.
      WARNING: Don't do this without dumping th elogs first!
      $ ykman bio clear
    """
    dev = ctx.obj['dev']
    ctx.obj['controller'] = BioController(dev.driver)


@bio.command('dump-logs')
@click.pass_context
@click.argument('logfile', type=click.File('w'), metavar='LOGFILE')
def dump_logs(ctx, logfile):
    """
    Dump the stored logs to a file.

    \b
    LOGFILE File to write log data to. Use '-' to use stdout.
    """

    n_keys = len(list(get_descriptors()))
    if n_keys > 1:
        ctx.fail('Only one YubiKey can be connected to perform this action.')

    def prompt_re_insert_key():
        click.echo('Remove and re-insert your YubiKey to dump logs...')

        removed = False
        while True:
            sleep(0.1)
            n_keys = len(list(get_descriptors()))
            if not n_keys:
                removed = True
            if removed and n_keys == 1:
                return

    prompt_re_insert_key()

    dev = list(get_descriptors())[0].open_device(TRANSPORT.CCID)
    controller = BioController(dev.driver)

    controller.dump_logs(logfile)


@bio.command()
@click.pass_context
def clear(ctx):
    """
    Clear the logs from the device.
    WARNING: Do NOT do this without first saving the logs to a file.
    """
    if not click.confirm(
        'WARNING! This will delete all logs stored on the ' 'YubiKey. Proceed?',
        err=True,
    ):
        ctx.abort()

    controller = ctx.obj['controller']
    controller.clear_logs()
