import traceback
import click
from click.testing import CliRunner
from ykman.cli.__main__ import cli


def ykman_cli(*argv, **kwargs):
    runner = CliRunner()
    result = runner.invoke(cli, list(argv), obj={}, **kwargs)
    if result.exit_code != 0:
        click.echo(result.output)
        traceback.print_tb(result.exc_info[2])
        raise result.exception
    return result.output
