import datetime
import logging
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


logger = logging.getLogger(__name__)

PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def open_file(*relative_path):
    return open(os.path.join(PKG_DIR, "files", *relative_path), "rb")


def generate_self_signed_certificate(
    common_name="Test", valid_from=None, valid_to=None
):

    valid_from = valid_from if valid_from else datetime.datetime.utcnow()
    valid_to = valid_to if valid_to else valid_from + datetime.timedelta(days=1)

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    return (
        x509.CertificateBuilder()
        .public_key(public_key)
        .subject_name(subject)
        .issuer_name(subject)  # Same as subject on self-signed certificate.
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
    ).sign(private_key, hashes.SHA256(), default_backend())
