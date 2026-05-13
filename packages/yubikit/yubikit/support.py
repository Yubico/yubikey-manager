# Copyright (c) 2015-2022 Yubico AB
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

import logging
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from _yubikit_native.device import get_name as _get_name_native
from _yubikit_native.device import read_info as _read_info_native
from yubikit.core import ApplicationNotAvailableError
from yubikit.core.smartcard import ApduError, SmartCardConnection
from yubikit.core.smartcard.scp import KeyRef, Scp11KeyParams
from yubikit.securitydomain import SecurityDomainSession

from .core import (
    PID,
    TRANSPORT,
    YUBIKEY,
    Connection,
)
from .management import (
    CAPABILITY,
    DeviceInfo,
    _device_info_from_native,
)

logger = logging.getLogger(__name__)


_BASE_NEO_APPS = CAPABILITY.OTP | CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP


def read_info(conn: Connection, pid: PID | None = None) -> DeviceInfo:
    """Reads out DeviceInfo from a YubiKey, or attempts to synthesize the data.

    Reading DeviceInfo from a ManagementSession is only supported for newer YubiKeys.
    This function attempts to read that information, but will fall back to gathering the
    data using other mechanisms if needed. It will also make adjustments to the data if
    required, for example to "fix" known bad values.

    The *pid* parameter must be provided whenever the YubiKey is connected via USB.

    :param conn: A connection to a YubiKey.
    :param pid: The USB Product ID.
    """

    logger.debug(f"Attempting to read device info, using {type(conn).__name__}")

    d = _read_info_native(conn)
    return _device_info_from_native(d)


def get_name(info: DeviceInfo, key_type: YUBIKEY | None) -> str:
    """Determine the product name of a YubiKey

    :param info: The device info.
    :param key_type: The YubiKey hardware platform.
    """
    return _get_name_native(
        version=(info.version[0], info.version[1], info.version[2]),
        form_factor=int(info.form_factor),
        is_sky=info.is_sky,
        is_fips=info.is_fips,
        pin_complexity=info.pin_complexity,
        serial=info.serial,
        usb_supported=int(
            info.supported_capabilities.get(TRANSPORT.USB, CAPABILITY(0))
        ),
        has_nfc=info.has_transport(TRANSPORT.NFC),
    )


def find_scp11_params(
    connection: SmartCardConnection,
    kid: int,
    kvn: int,
    root_ca: x509.Certificate | None = None,
) -> Scp11KeyParams:
    if root_ca:
        try:
            ski = root_ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound:
            ski = None
    else:
        ski = None

    try:
        with SecurityDomainSession(connection) as scp:
            if not kvn:
                if ski:
                    # Find by CA
                    ca_ski = ski.value.digest
                    for ref, ca_check in scp.get_supported_ca_identifiers(
                        klcc=True
                    ).items():
                        if ca_check == ca_ski:
                            if not kid or ref.kid == kid:
                                kid, kvn = ref
                                break
                    else:
                        raise ValueError(
                            f"No CA identifier found matching SKI: {ca_ski.hex()}"
                        )
                # Find any matching KID
                for ref in scp.get_key_information().keys():
                    if ref.kid == kid:
                        kvn = ref.kvn
                        break
                else:
                    raise ValueError(f"No SCP key found matching KID=0x{kid:x}")

            ref = KeyRef(kid, kvn)
            try:
                chain = scp.get_certificate_bundle(ref)
                if not chain:
                    raise ValueError(f"No certificate chain stored for {ref}")
                if root_ca:
                    logger.debug("Validating KLCC CA using supplied file")
                    parent = root_ca
                    for cert in chain:
                        # Requires cryptography >= 40
                        cert.verify_directly_issued_by(parent)
                        parent = cert
                    logger.info("KLCC CA validated")
                else:
                    logger.info("No CA supplied, skipping KLCC CA validation")

                pub_key = cast(EllipticCurvePublicKey, chain[-1].public_key())
                return Scp11KeyParams(ref, pub_key)
            except ApduError:
                raise ValueError(f"Unable to get SCP key paramaters ({ref})")

    except ApplicationNotAvailableError:
        raise ValueError("Security Domain application not available")
