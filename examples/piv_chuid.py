import sys
from datetime import date
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from yubikit.piv import Chuid, FascN

# Load key and certificate from files
key_name, cert_name = sys.argv[1:]
with open(cert_name, "rb") as f:
    cert_bytes = f.read()
cert = x509.load_pem_x509_certificate(cert_bytes)
with open(key_name, "rb") as f:
    key_bytes = f.read()
key = serialization.load_pem_private_key(key_bytes, None)

# Create an unsigned CHUID
chuid = Chuid(
    # Non-Federal Issuer FASC-N
    fasc_n=FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1),
    guid=uuid4().bytes,
    # Expires on: 2030-01-01
    expiration_date=date(2030, 1, 1),
)

# Create a signer for the CHUID
signer = chuid.get_signer(cert)

if isinstance(key, ec.EllipticCurvePrivateKey):
    signature = key.sign(
        signer.tbs_bytes,
        cert.signature_algorithm_parameters,  # type: ignore
    )
elif isinstance(key, rsa.RSAPrivateKey):
    signature = key.sign(
        signer.tbs_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,  # type: ignore
    )
else:
    raise TypeError("Unsupported key type")

# Sign the CHUID
asymmetric_signature = signer.sign(signature)

print("Signature:", asymmetric_signature.hex())

# Attach the signature to the CHUID
chuid.asymmetric_signature = asymmetric_signature
print("CHUID:", bytes(chuid).hex())
