import pytest
import contextlib
import io


def test_fail_on_alias(ykman_cli):
    with io.StringIO() as buf:
        with contextlib.redirect_stderr(buf):
            with pytest.raises(SystemExit):
                ykman_cli("oath", "code")
        err = buf.getvalue()

    assert "oath accounts code" in err
