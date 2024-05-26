# Copyright (c) 2024 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from yubikit.core.smartcard import SmartCardConnection, ApduError, SW
from yubikit.core.smartcard.scp import (
    ScpKid,
    KeyRef,
    Scp03KeyParams,
    Scp11KeyParams,
    StaticKeys,
)
from yubikit.management import CAPABILITY
from yubikit.securedomain import SecureDomainSession

from ..util import (
    parse_private_key,
    parse_certificates,
    InvalidPasswordError,
)
from .util import (
    CliFail,
    click_group,
    click_force_option,
    click_postpone_execution,
    click_callback,
    click_prompt,
    HexIntParamType,
    pretty_print,
    get_scp_params,
    organize_scp11_certificates,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from typing import Dict, List, Any

import click
import logging
import sys


logger = logging.getLogger(__name__)


@click_group(
    "sd", connections=[SmartCardConnection], hidden="--full-help" not in sys.argv
)
@click.pass_context
@click_postpone_execution
def securedomain(ctx):
    """
    Manage the Secure Domain application, which holds keys for SCP.
    """

    dev = ctx.obj["device"]
    conn = dev.open_connection(SmartCardConnection)
    ctx.call_on_close(conn.close)

    session = SecureDomainSession(conn)
    scp_params = get_scp_params(ctx, CAPABILITY(-1), conn)

    if scp_params:
        session.authenticate(scp_params)

    ctx.obj["authenticated"] = (
        isinstance(scp_params, Scp03KeyParams)
        or isinstance(scp_params, Scp11KeyParams)
        and scp_params.ref.kid == ScpKid.SCP11a
    )

    ctx.obj["session"] = session


@securedomain.command()
@click.pass_context
def info(ctx):
    """
    List keys in the Secure Domain of the YubiKey.
    """
    sd = ctx.obj["session"]
    data: List[Any] = []
    cas = sd.get_supported_ca_identifiers()
    for ref in sd.get_key_information().keys():
        if ref.kid < 0x10:  # SCP03
            data.append(f"{ref}")
        else:  # SCP11
            inner: Dict[str, Any] = {}
            if ref in cas:
                inner["CA Key Identifier"] = ":".join(f"{b:02X}" for b in cas[ref])
            try:
                inner["Certificate chain"] = [
                    c.subject.rfc4514_string() for c in sd.get_certificate_bundle(ref)
                ]
            except ApduError:
                pass
            data.append({ref: inner})

    click.echo("\n".join(pretty_print(data)))


@securedomain.command()
@click.pass_context
@click_force_option
def reset(ctx, force):
    """
    Reset all Secure Domain data.

    This action will wipe all keys and restore factory settings for
    the Secure Domain on the YubiKey.
    """
    if "scp" in ctx.obj:
        raise CliFail("Reset must be performed without an active SCP session")

    force or click.confirm(
        "WARNING! This will delete all stored Secure Domain data and restore factory "
        "settings. Proceed?",
        abort=True,
        err=True,
    )

    click.echo("Resetting Secure Domain data...")
    ctx.obj["session"].reset()

    click.echo("Success! Secure Domain data has been cleared from the YubiKey.")
    click.echo("Your YubiKey now has the default SCP key set")


@securedomain.group()
def keys():
    """Manage SCP keys."""


def _require_auth(ctx):
    if not ctx.obj["authenticated"]:
        raise CliFail("This command requires authentication, invoke ykman with --scp.")


def _fname(fobj):
    return getattr(fobj, "name", fobj)


@click_callback()
def click_parse_scp_ref(ctx, param, val):
    try:
        return KeyRef(*val)
    except AttributeError:
        raise ValueError(val)


class ScpKidParamType(HexIntParamType):
    name = "kid"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        try:
            name = value.upper()[:-1] + value[-1].lower()
            return ScpKid[name]
        except KeyError:
            try:
                if value.lower().startswith("0x"):
                    return int(value[2:], 16)
                if ":" in value:
                    return int(value.replace(":", ""), 16)
                return int(value)
            except ValueError:
                self.fail(f"{value!r} is not a valid integer", param, ctx)


click_key_argument = click.argument(
    "key",
    metavar="KID KVN",
    type=(ScpKidParamType(), HexIntParamType()),
    callback=click_parse_scp_ref,
)


@keys.command("generate")
@click.pass_context
@click_key_argument
@click.argument("public-key-output", type=click.File("wb"), metavar="PUBLIC-KEY")
def generate_key(ctx, key, public_key_output):
    """
    Generate an asymmetric key pair.

    The private key is generated on the YubiKey, and written to one of the slots.

    \b
    KID KVN     key reference for the new key
    PUBLIC-KEY  file containing the generated public key (use '-' to use stdout)
    """

    _require_auth(ctx)
    valid = (ScpKid.SCP11a, ScpKid.SCP11b, ScpKid.SCP11c)
    if key.kid not in valid:
        values_str = ", ".join(f"0x{v:x} ({v.name})" for v in valid)
        raise CliFail(f"KID must be one of {values_str}")

    session = ctx.obj["session"]

    public_key = session.generate_ec_key(key)

    key_encoding = serialization.Encoding.PEM
    public_key_output.write(
        public_key.public_bytes(
            encoding=key_encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    logger.info(
        f"Private key generated for {key}, public key written to "
        f"{_fname(public_key_output)}"
    )


@keys.command("import")
@click.pass_context
@click_key_argument
@click.argument("input", metavar="INPUT")
@click.option("-p", "--password", help="password used to decrypt the file (if needed)")
def import_key(ctx, key, input, password):
    """
    Import a key or certificate.

    KID 0x01 expects the input to be a ":"-separated triple of K-ENC:K-MAC:K-DEK.

    KID 0x11, 0x13, and 0x15 expect the input to be a file containing a private key and
    (optionally) a certificate chain.

    KID 0x10, 0x20-0x2F expect the file to contain a CA-KLOC certificate.

    \b
    KID KVN     key reference for the new key
    INPUT       SCP03 keyset, or input file (use '-' to use stdin)
    """

    _require_auth(ctx)
    session = ctx.obj["session"]

    if key.kid == ScpKid.SCP03:
        session.put_key(key, StaticKeys(*[bytes.fromhex(k) for k in input.split(":")]))
        return

    file = click.File("rb").convert(input, None, ctx)
    data = file.read()
    if key.kid in (ScpKid.SCP11a, ScpKid.SCP11b, ScpKid.SCP11c):
        # Expect a private key
        while True:
            if password is not None:
                password = password.encode()
            try:
                target = parse_private_key(data, password)
                break
            except InvalidPasswordError:
                logger.debug("Error parsing file", exc_info=True)
                if password is None:
                    password = click_prompt(
                        "Enter password to decrypt file",
                        default="",
                        hide_input=True,
                        show_default=False,
                    )
                else:
                    password = None
                    click.echo("Wrong password.")

        ca, bundle, leaf = organize_scp11_certificates(
            parse_certificates(data, password)
        )
        if leaf:
            bundle = list(bundle) + [leaf]

    elif key.kid in (0x10, *range(0x20, 0x30)):  # Public CA key
        ca, inter, leaf = organize_scp11_certificates(parse_certificates(data, None))
        if not ca:
            raise CliFail("Input does not contain a valid CA-KLOC certificate")
        target = ca.public_key()
        bundle = None

    else:
        raise CliFail(f"Invalid value for KID={key.kid:x}")

    session.put_key(key, target)

    # If we have a bundle of intermediate certificates, store them
    if bundle:
        session.store_certificate_bundle(key, bundle)

    # If the CA has a Subject Key Identifer we should store it
    if ca:
        ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        session.store_ca_issuer(key, ski.value.digest)


@keys.command()
@click.pass_context
@click_key_argument
@click.argument("certificates-output", type=click.File("wb"), metavar="OUTPUT")
def export(ctx, key, certificates_output):
    """
    Export certificate chain for a key.

    \b
    KID KVN     key reference to output certificate chain for
    OUTPUT      file to write the certificate chain to (use '-' to use stdout)
    """
    session = ctx.obj["session"]
    pems = [
        cert.public_bytes(encoding=serialization.Encoding.PEM)
        for cert in reversed(session.get_certificate_bundle(key))
    ]
    if pems:
        certificates_output.write(b"".join(pems))
        logger.info(
            f"Certificate chain for {key} written to {_fname(certificates_output)}"
        )
    else:
        raise CliFail(f"No certificate chain stored for {key}")


@keys.command("delete")
@click.pass_context
@click_key_argument
def delete_key(ctx, key):
    """
    Delete a key or keyset.

    Deletes the key or keyset with the given KID and KVN. Set either KID or KVN to 0 to
    use it as a wildcard and delete all keys matching the specific KID or KVN

    \b
    KID KVN     key reference for the key to delete
    """
    _require_auth(ctx)
    session = ctx.obj["session"]
    try:
        session.delete_key(key.kid, key.kvn)
    except ApduError as e:
        if e.sw == SW.REFERENCE_DATA_NOT_FOUND:
            raise CliFail(f"No key stored in {key}.")
        raise


@keys.command("set-allowlist")
@click.pass_context
@click_key_argument
@click.argument("serials", nargs=-1, type=HexIntParamType())
def set_allowlist(ctx, key, serials):
    """
    Set an allowlist of certificate serial numbers for a key.

    Each certificate in the chain used when authenticating an SCP11a/c session will be
    checked and rejected if their serial number is not in this allowlist.

    \b
    KID KVN     key reference to set the allowlist for
    SERIALS     serial numbers of certificates to allow (space separated)
    """
    _require_auth(ctx)
    session = ctx.obj["session"]

    session.store_allowlist(key, serials)
