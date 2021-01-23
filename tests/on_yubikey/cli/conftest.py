from yubikit.core import TRANSPORT
from ykman.cli.__main__ import cli
from ykman.cli.aliases import apply_aliases
from click.testing import CliRunner
from functools import partial
import pytest


@pytest.fixture(scope="module")
def ykman_cli(device, info):
    if device.transport == TRANSPORT.NFC:
        return partial(_ykman_cli, "--reader", device.reader.name)
    else:
        return partial(_ykman_cli, "--device", info.serial)


def _ykman_cli(*argv, **kwargs):
    argv = apply_aliases(["ykman"] + [str(a) for a in argv])
    runner = CliRunner()
    result = runner.invoke(cli, argv[1:], obj={}, **kwargs)
    if result.exit_code != 0:
        raise result.exception
    return result
