from click.testing import CliRunner
from ykman.cli.__main__ import cli


def ykman_cli(*argv, **kwargs):
    runner = CliRunner()
    result = runner.invoke(cli, list(argv), obj={}, **kwargs)
    if result.exit_code != 0:
        raise result.exception
    return result.output
