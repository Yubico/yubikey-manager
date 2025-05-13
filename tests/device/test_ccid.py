import pytest

from yubikit.core.smartcard import ApplicationNotAvailableError, SmartCardProtocol


def test_select_wrong_app(ccid_connection):
    p = SmartCardProtocol(ccid_connection)
    with pytest.raises(ApplicationNotAvailableError):
        p.select(b"not_a_real_aid")
