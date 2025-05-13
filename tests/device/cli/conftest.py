import logging
from functools import partial

import pytest
from click.testing import CliRunner

from ykman._cli.__main__ import cli
from ykman._cli.util import CliFail
from yubikit.core import TRANSPORT

logger = logging.getLogger(__name__)


@pytest.fixture()
def ykman_cli(capsys, device, info):
    def _ykman_cli(*argv, **kwargs):
        runner = CliRunner()
        with capsys.disabled():
            logger.debug("CLI: ykman %r", argv)
            result = runner.invoke(cli, argv, obj={}, **kwargs)
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
