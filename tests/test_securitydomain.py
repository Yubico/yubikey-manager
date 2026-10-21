import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from yubikit.core import NotSupportedError
from yubikit.securitydomain import Curve


@pytest.mark.parametrize("curve", Curve, ids=lambda curve: curve.name)
@pytest.mark.parametrize("public", (False, True), ids=("private", "public"))
def test_curve_from_key_accepts_only_p256(curve, public):
    private_key = ec.generate_private_key(curve._curve)
    key = private_key.public_key() if public else private_key
    if curve == Curve.SECP256R1:
        assert Curve._from_key(key) == Curve.SECP256R1
    else:
        with pytest.raises(NotSupportedError, match="Only P-256 EC keys"):
            Curve._from_key(key)
