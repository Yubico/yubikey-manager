from yubikit.management import FORM_FACTOR


def test_form_factor_from_code():
    for ff in FORM_FACTOR:
        assert ff == FORM_FACTOR.from_code(ff)
