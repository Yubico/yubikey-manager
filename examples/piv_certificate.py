"""
This script will program an x.509 certificate into a slot of a YubiKey.

By using a script instead of the command line interface, we are able to fully customize
the certificate with arbitrary fields, extensions, etc.

This script is mainly intended as a template, to be customized according to your
liking. For more details on this, see:

https://cryptography.io/en/latest/x509/reference/#x-509-certificate-builder
https://cryptography.io/en/latest/x509/reference/#object-identifiers

This script generates a self-signed certificate, but can be easily altered to instead
use a different public key.

NOTE: This same approach can be used to generate a CSR, see:

https://cryptography.io/en/latest/x509/reference/#x-509-csr-certificate-signing-request-builder-object

And instead use sign_csr_builder instead of sign_certificate_builder.

Usage: piv_certificate.py
"""

import datetime

import click
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from ykman import scripting as s
from ykman.piv import sign_certificate_builder
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    SLOT,
    PivSession,
)

# Use slot 9A (authentication), and key type RSA 2048
slot = SLOT.AUTHENTICATION
key_type = KEY_TYPE.RSA2048

# Connect to a YubiKey
yubikey = s.single()

# Establish a PIV session
piv = PivSession(yubikey.smart_card())

click.echo("WARNING")
click.echo(f"This will overwrite any key already in slot {slot:X} of the YubiKey!")
click.echo("")

# Unlock with the management key
key = click.prompt(
    "Enter management key", default=DEFAULT_MANAGEMENT_KEY.hex(), hide_input=True
)

piv.authenticate(bytes.fromhex(key))

# Generate a private key on the YubiKey
print(f"Generating {key_type.name} key in slot {slot:X}...")
pub_key = piv.generate_key(slot, key_type)

now = datetime.datetime.now()

# Prepare the subject:
subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Stockholm"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Co"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example Certificate"),
    ]
)

# Prepare the certificate
builder = (
    x509.CertificateBuilder()
    .issuer_name(subject)  # Same as subject since this is self-signed
    .subject_name(subject)
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=7))  # 7 day validity
    .serial_number(x509.random_serial_number())
    .public_key(pub_key)
    # Some examples of extensions to add, many more are possible:
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    .add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName("example.com"),
            ]
        ),
        critical=False,
    )
)


# Verify the PIN
pin = click.prompt("Enter PIN", hide_input=True)
piv.verify_pin(pin)

# Sign the certificate
certificate = sign_certificate_builder(piv, slot, key_type, builder)
pem = certificate.public_bytes(serialization.Encoding.PEM)

click.echo("Certificate generated!")
click.echo("")

# Print the certificate
print(pem.decode())
