from click.testing import CliRunner
from ykman.cli.__main__ import cli
import os


PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def open_file(*relative_path):
    return open(os.path.join(PKG_DIR, 'files', *relative_path), 'rb')


def ykman_cli(*argv, **kwargs):
    runner = CliRunner()
    result = runner.invoke(cli, list(argv), obj={}, **kwargs)
    if result.exit_code != 0:
        raise result.exception
    return result.output
