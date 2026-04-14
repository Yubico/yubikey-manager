import pytest
from yubikit.core.smartcard import ApplicationNotAvailableError, SmartCardProtocol


def test_select_wrong_app(ccid_connection):
    with SmartCardProtocol(ccid_connection) as p:
        with pytest.raises(ApplicationNotAvailableError):
            p.select(b"not_a_real_aid")
