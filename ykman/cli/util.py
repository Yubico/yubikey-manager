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

import functools
import click
import sys
from ..util import parse_b32_key
from collections import OrderedDict

click_force_option = click.option('-f', '--force', is_flag=True,
                                  help='Confirm the action without prompting.')


class UpperCaseChoice(click.Choice):
    """
    Support lowercase option values for uppercase options.
    Does not support token normalization.
    """
    def __init__(self, choices):
        click.Choice.__init__(self, choices)

    def convert(self, value, param, ctx):
        if value.upper() in self.choices:
            return value.upper()
        self.fail(
            'invalid choice: %s. (choose from %s)' % (
                value, ', '.join(self.choices)), param, ctx)


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


class YkmanContext(object):
    def __init__(self):
        self._resolved = False
        self._objects = OrderedDict()

    @classmethod
    def get(cls, ctx):
        if not ctx.obj.get('_resolver'):
            ctx.obj['_resolver'] = cls()
        return ctx.obj['_resolver']

    def add_resolver(self, key, f):
        if self._resolved:
            f = f()
        self._objects[key] = f

    def resolve(self):
        if not self._resolved:
            self._resolved = True
            for k, f in self._objects.items():
                self._objects[k] = f()

    def __getitem__(self, key):
        self.resolve()
        return self._objects[key]

    def __setitem__(self, key, value):
        if not self._resolved:
            raise ValueError('BUG: Attempted to set item when unresolved.')
        self._objects[key] = value


def click_postpone_execution(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        YkmanContext.get(click.get_current_context()).add_resolver(
            str(f),
            lambda: f(*args, **kwargs)
        )
    return inner


@click_callback()
def click_parse_b32_key(ctx, param, val):
    return parse_b32_key(val)


def prompt_for_touch():
    try:
        click.echo('Touch your YubiKey...', err=True)
    except Exception:
        sys.stderr.write('Touch your YubiKey...\n')
