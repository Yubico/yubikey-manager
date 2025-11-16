import pytest

from yubikit.management import FORM_FACTOR


@pytest.mark.parametrize("form_factor", list(FORM_FACTOR))
def test_form_factor_from_code_accepts_enum_members(form_factor):
    assert form_factor == FORM_FACTOR.from_code(form_factor)
