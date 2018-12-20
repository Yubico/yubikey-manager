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

from .util import click_force_option
from ..util import Mode, TRANSPORT
from ..driver import ModeSwitchError
import logging
import re
import click


logger = logging.getLogger(__name__)


def _parse_transport_string(transport):
    for t in TRANSPORT:
        if t.name.startswith(transport):
            return t
    raise ValueError()


def _parse_mode_string(ctx, param, mode):
    if mode is None:
        return None
    try:
        mode_int = int(mode)
        return Mode.from_code(mode_int)
    except IndexError:
        ctx.fail('Invalid mode: {}'.format(mode_int))
    except ValueError:
        pass  # Not a numeric mode, parse string

    try:
        transports = set()
        if mode[0] in ['+', '-']:
            transports.update(TRANSPORT.split(ctx.obj['dev'].mode.transports))
            for mod in re.findall(r'[+-][A-Z]+', mode.upper()):
                transport = _parse_transport_string(mod[1:])
                if mod.startswith('+'):
                    transports.add(transport)
                else:
                    transports.discard(transport)
        else:
            for t in filter(None, re.split(r'[+]+', mode.upper())):
                transports.add(_parse_transport_string(t))
    except ValueError:
        ctx.fail('Invalid mode string: {}'.format(mode))

    return Mode(sum(transports))


@click.command()
@click.argument('mode', required=False, callback=_parse_mode_string)
@click.option('--touch-eject', is_flag=True, help='When set, the button '
              'toggles the state of the smartcard between ejected and inserted '
              '(CCID mode only).')
@click.option('--autoeject-timeout', required=False, type=int, default=0,
              metavar='SECONDS',
              help='When set, the smartcard will automatically eject after the '
              'given time. Implies --touch-eject (CCID mode only).'
              )
@click.option('--chalresp-timeout', required=False, type=int, default=0,
              metavar='SECONDS',
              help='Sets the timeout when waiting for touch for challenge '
              'response.')
@click_force_option
@click.pass_context
def mode(ctx, mode, touch_eject, autoeject_timeout, chalresp_timeout, force):
    """
    Manage connection modes (USB Interfaces).

    Get the current connection mode of the YubiKey, or set it to MODE.

    MODE can be a string, such as "OTP+FIDO+CCID", or a shortened form: "o+f+c".
    It can also be a mode number.

    Examples:

    \b
      Set the OTP and FIDO mode:
      $ ykman mode OTP+FIDO

    \b
      Set the CCID only mode and use touch to eject the smart card:
      $ ykman mode CCID --touch-eject
    """
    dev = ctx.obj['dev']
    if autoeject_timeout:
        touch_eject = True
    autoeject = autoeject_timeout if touch_eject else None

    if mode is not None:
        if mode.transports != TRANSPORT.CCID:
            autoeject = None
            if touch_eject:
                ctx.fail('--touch-eject can only be used when setting'
                         ' CCID-only mode')

        if not force:
            if mode == dev.mode:
                click.echo('Mode is already {}, nothing to do...'.format(mode))
                ctx.exit()
            elif not dev.has_mode(mode):
                click.echo('Mode {} is not supported on this YubiKey!'
                           .format(mode))
                ctx.fail('Use --force to attempt to set it anyway.')
            force or click.confirm('Set mode of YubiKey to {}?'.format(mode),
                                   abort=True, err=True)

        try:
            dev.set_mode(mode, chalresp_timeout, autoeject)
            if not dev.can_write_config:
                click.echo(
                    'Mode set! You must remove and re-insert your YubiKey '
                    'for this change to take effect.')
        except ModeSwitchError as e:
            logger.debug('Failed to switch mode', exc_info=e)
            click.echo('Failed to switch mode on the YubiKey. Make sure your '
                       'YubiKey does not have an access code set.')

    else:
        click.echo('Current connection mode is: {}'.format(dev.mode))
        supported = ', '.join(t.name for t in TRANSPORT
                              .split(dev.config.usb_supported))
        click.echo('Supported USB interfaces are: {}'.format(supported))
