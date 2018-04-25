from binascii import a2b_hex
from click.testing import CliRunner
from ykman.cli.__main__ import cli
import os
import sys


PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def open_file(*relative_path):
    return open(os.path.join(PKG_DIR, 'files', *relative_path), 'rb')


def ykman_cli(*argv, **kwargs):
    runner = CliRunner()
    result = runner.invoke(cli, list(argv), obj={}, **kwargs)
    if result.exit_code != 0:
        raise result.exception
    return result.output


def a2b_hex_if_text(data):
    if sys.version_info < (3, 0):
        if len(data) > 0:
            d = data[0]
            if (d >= '0' and d <= '9') or (d >= 'a' and d <= 'f'):
                return a2b_hex(data)
    else:
        if type(data) is str:
            return a2b_hex(data)

    return data
