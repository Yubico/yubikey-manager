from yubikit.management import CAPABILITY
from ... import condition
from .util import DEFAULT_PIN, DEFAULT_PUK, DEFAULT_MANAGEMENT_KEY
from typing import NamedTuple
import pytest


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.PIV)
def ensure_piv(ykman_cli):
    ykman_cli("piv", "reset", "-f")


class Keys(NamedTuple):
    pin: str
    puk: str
    mgmt: str


@pytest.fixture
def default_keys():
    yield Keys(DEFAULT_PIN, DEFAULT_PUK, DEFAULT_MANAGEMENT_KEY)


@pytest.fixture
def keys(ykman_cli, info, default_keys):
    if CAPABILITY.PIV in info.fips_capable:
        new_keys = Keys(
            "12345679",
            "12345670",
            "010203040506070801020304050607080102030405060709",
        )

        ykman_cli(
            "piv", "access", "change-pin", "-P", default_keys.pin, "-n", new_keys.pin
        )
        ykman_cli(
            "piv", "access", "change-puk", "-p", default_keys.puk, "-n", new_keys.puk
        )
        ykman_cli(
            "piv",
            "access",
            "change-management-key",
            "-m",
            default_keys.mgmt,
            "-n",
            new_keys.mgmt,
            "-f",
        )

        yield new_keys
    else:
        yield default_keys
