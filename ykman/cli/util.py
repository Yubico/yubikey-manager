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
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.oath import parse_b32_key
from collections import OrderedDict
from collections.abc import MutableMapping
from cryptography.hazmat.primitives import serialization
from contextlib import contextmanager
from threading import Timer


class EnumChoice(click.Choice):
    """
    Use an enum's member names as the definition for a choice option.

    Enum member names MUST be all uppercase. Options are not case sensitive.
    Underscores in enum names are translated to dashes in the option choice.
    """

    def __init__(self, choices_enum, hidden=[]):
        super().__init__(
            [v.name.replace("_", "-") for v in choices_enum if v not in hidden],
            case_sensitive=False,
        )
        self.choices_enum = choices_enum

    def convert(self, value, param, ctx):
        name = super(EnumChoice, self).convert(value, param, ctx).replace("-", "_")
        return self.choices_enum[name]


class _YkmanCommand(click.Command):
    def __init__(self, name=None, **attrs):
        self.interfaces = attrs.pop("interfaces", None)
        click.Command.__init__(self, name, **attrs)


class _YkmanGroup(click.Group):
    """click.Group which returns commands before subgroups in list_commands."""

    def __init__(self, name=None, commands=None, **attrs):
        self.connections = attrs.pop("connections", None)
        click.Group.__init__(self, name, commands, **attrs)

    def list_commands(self, ctx):
        return sorted(
            self.commands, key=lambda c: (isinstance(self.commands[c], click.Group), c)
        )


def ykman_group(
    connections=[SmartCardConnection, OtpConnection, FidoConnection], *args, **kwargs
):
    if not isinstance(connections, list):
        connections = [connections]  # Single type
    return click.group(cls=_YkmanGroup, *args, connections=connections, **kwargs)


def ykman_command(interfaces, *args, **kwargs):
    return click.command(cls=_YkmanCommand, *args, interfaces=interfaces, **kwargs)


def click_callback(invoke_on_missing=False):
    def wrap(f):
        @functools.wraps(f)
        def inner(ctx, param, val):
            if not invoke_on_missing and not param.required and val is None:
                return None
            try:
                return f(ctx, param, val)
            except ValueError as e:
                ctx.fail(f'Invalid value for "{param.name}": {str(e)}')

        return inner

    return wrap


@click_callback()
def click_parse_format(ctx, param, val):
    if val == "PEM":
        return serialization.Encoding.PEM
    elif val == "DER":
        return serialization.Encoding.DER
    else:
        raise ValueError(val)


click_force_option = click.option(
    "-f", "--force", is_flag=True, help="Confirm the action without prompting."
)


click_format_option = click.option(
    "-F",
    "--format",
    type=click.Choice(["PEM", "DER"], case_sensitive=False),
    default="PEM",
    show_default=True,
    help="Encoding format.",
    callback=click_parse_format,
)


class YkmanContextObject(MutableMapping):
    def __init__(self):
        self._objects = OrderedDict()
        self._resolved = False

    def add_resolver(self, key, f):
        if self._resolved:
            f = f()
        self._objects[key] = f

    def resolve(self):
        if not self._resolved:
            self._resolved = True
            for k, f in self._objects.copy().items():
                self._objects[k] = f()

    def __getitem__(self, key):
        self.resolve()
        return self._objects[key]

    def __setitem__(self, key, value):
        if not self._resolved:
            raise ValueError("BUG: Attempted to set item when unresolved.")
        self._objects[key] = value

    def __delitem__(self, key):
        del self._objects[key]

    def __len__(self):
        return len(self._objects)

    def __iter__(self):
        return iter(self._objects)


def click_postpone_execution(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        click.get_current_context().obj.add_resolver(str(f), lambda: f(*args, **kwargs))

    return inner


@click_callback()
def click_parse_b32_key(ctx, param, val):
    return parse_b32_key(val)


def click_prompt(prompt, err=True, **kwargs):
    """Replacement for click.prompt to better work when piping input to the command.

    Note that we change the default of err to be True, since that's how we typically
    use it.
    """
    if not sys.stdin.isatty():  # Piped from stdin, see if there is data
        line = sys.stdin.readline()
        if line:
            return line.rstrip("\n")

    # No piped data, use standard prompt
    return click.prompt(prompt, err=err, **kwargs)


def prompt_for_touch():
    try:
        click.echo("Touch your YubiKey...", err=True)
    except Exception:
        sys.stderr.write("Touch your YubiKey...\n")


@contextmanager
def prompt_timeout(timeout=0.5):
    timer = Timer(timeout, prompt_for_touch)
    try:
        yield timer.start()
    finally:
        timer.cancel()


def cli_fail(message: str, code: int = 1):
    click.echo(f"Error: {message}", err=True)
    sys.exit(code)
