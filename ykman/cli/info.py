# Copyright (c) 2016 Yubico AB
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

from ..util import CAPABILITY
import click


@click.command()
@click.pass_context
def info(ctx):
    """
    Show general information.

    Displays information about the attached YubiKey such as serial number,
    firmware version, capabilities, etc.
    """
    dev = ctx.obj['dev']
    click.echo('Device name: {}'.format(dev.device_name))
    click.echo('Serial number: {}'.format(
        dev.serial or 'Not set or unreadable'))
    f_version = '.'.join(str(x) for x in dev.version)
    click.echo('Firmware version: {}'.format(f_version))
    click.echo('Enabled connection(s): {}'.format(dev.mode))
    click.echo()

    click.echo('Device capabilities:')
    for c in CAPABILITY:
        if c != CAPABILITY.NFC:  # For now, don't expose NFC Capability
            if c & dev.capabilities:
                if c & dev.enabled:
                    status = 'Enabled'
                else:
                    status = 'Disabled'
            else:
                status = 'Not available'

            click.echo('    {0.name}:\t{1}'.format(c, status))
