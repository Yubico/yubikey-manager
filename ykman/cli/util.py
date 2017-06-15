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
import functools
import click
import sys
from ..util import parse_b32_key

click_force_option = click.option('-f', '--force', is_flag=True,
                                  help='Confirm the action without prompting.')


def click_callback(invoke_on_missing=False):
    def wrap(f):
        @functools.wraps(f)
        def inner(ctx, param, val):
            if not invoke_on_missing and not param.required and val is None:
                return None
            try:
                return f(ctx, param, val)
            except Exception as e:
                ctx.fail('Invalid value for "{}": {}'.format(
                    param.name, str(e)))
        return inner
    return wrap


def click_skip_on_help(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        ctx = click.get_current_context()
        for arg in ctx.help_option_names:
            if arg in sys.argv:
                return
        f(*args, **kwargs)
    return inner


@click_callback()
def click_parse_b32_key(ctx, param, val):
    return parse_b32_key(val)


def prompt_for_touch():
    click.echo('Touch your YubiKey...')
