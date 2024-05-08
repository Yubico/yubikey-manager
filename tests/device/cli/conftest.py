from yubikit.core import TRANSPORT
from ykman._cli.__main__ import cli
from ykman._cli.aliases import apply_aliases
from ykman._cli.util import CliFail
from click.testing import CliRunner
from functools import partial
import pytest


@pytest.fixture()
def ykman_cli(capsys, device, info):
    def _ykman_cli(*argv, **kwargs):
        argv = apply_aliases(["ykman"] + [str(a) for a in argv])
        runner = CliRunner(mix_stderr=False)
        with capsys.disabled():
            result = runner.invoke(cli, argv[1:], obj={}, **kwargs)
        if result.exit_code != 0:
            if isinstance(result.exception, CliFail):
                raise SystemExit()
            raise result.exception
        return result

    if device.transport == TRANSPORT.NFC:
        return partial(_ykman_cli, "--reader", device.reader.name)
    elif info.serial is not None:
        return partial(_ykman_cli, "--device", info.serial)
    else:
        return _ykman_cli
