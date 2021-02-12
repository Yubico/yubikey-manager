from yubikit.core.smartcard import SmartCardProtocol, ApplicationNotAvailableError
import pytest


def test_select_wrong_app(ccid_connection):
    p = SmartCardProtocol(ccid_connection)
    with pytest.raises(ApplicationNotAvailableError):
        p.select(b"not_a_real_aid")
