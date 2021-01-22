from ykman.cli.__main__ import cli
from ykman.cli.aliases import apply_aliases
from click.testing import CliRunner
from functools import partial
import pytest


@pytest.fixture(scope="module")
def ykman_cli(info):
    return partial(ykman_cli_for_serial, info.serial)


def ykman_cli_for_serial(serial, *argv, **kwargs):
    argv = apply_aliases(["ykman"] + [str(a) for a in argv])
    runner = CliRunner()
    result = runner.invoke(cli, argv[1:], obj={}, **kwargs)
    if result.exit_code != 0:
        raise result.exception
    return result
