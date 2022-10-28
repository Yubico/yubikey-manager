# Copyright (c) 2021 Yubico AB
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

from .util import click_force_option, click_command
from .. import scripting  # noqa - make sure this file gets included by PyInstaller.

import sys
import click
import logging


logger = logging.getLogger(__name__)


_WARNING = """
WARNING: Never run a script without fully understanding what it does!

Scripts are very powerful, and have the power to harm to both your YubiKey and
your computer.

ONLY run scripts that you fully trust!
"""


def _add_warning(obj):
    obj.__doc__ = obj.__doc__.format("\n    ".join(_WARNING.splitlines()))
    return obj


@click_command(
    "script",
    context_settings=dict(ignore_unknown_options=True),
)
@click.pass_context
@click.option(
    "-s",
    "--site-dir",
    type=click.Path(exists=True),
    multiple=True,
    metavar="DIR",
    help="specify additional path(s) to load python modules from",
)
@click.argument("script", type=click.File("rb"), metavar="FILE")
@click.argument("arguments", nargs=-1, type=click.UNPROCESSED)
@click_force_option
@_add_warning
def run_script(ctx, site_dir, script, arguments, force):
    """
    Run a python script.

    {0}

    Argument can be passed to the script by adding them after the end of the
    command. These will be accessible inside the script as sys.argv, with the script
    name as the initial value. For more information on scripting, see the "Scripting"
    page in the documentation.

    Examples:

    \b
      Run the file "myscript.py", passing arguments "123456" and "indata.csv":
      $ ykman script myscript.py 123456 indata.csv

    """

    force or click.confirm(
        f"{_WARNING}\n"
        "You can bypass this message by running the command with the --force flag.\n\n"
        "Run script?",
        abort=True,
        err=True,
    )

    for sd in site_dir:
        logger.debug("Add %s to path.", sd)
        sys.path.append(sd)

    script_body = script.read()

    sys.argv = [script.name, *arguments]
    exec(script_body, {})  # nosec
