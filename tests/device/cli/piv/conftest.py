from yubikit.management import CAPABILITY
from ... import condition
import pytest


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.PIV)
def ensure_piv(ykman_cli):
    ykman_cli("piv", "reset", "-f")
