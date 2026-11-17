import pytest


def test_invalid_scp_params_are_validated_before_connection(
    scp_session_constructor, invalid_scp_params
):
    with pytest.raises(ValueError):
        scp_session_constructor(object(), scp_key_params=invalid_scp_params)
