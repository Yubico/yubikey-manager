# Copyright (c) 2015 Yubico AB
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

from yubikit.core.smartcard import (
    SmartCardConnection,
    SmartCardProtocol,
    ApduError,
    SW,
    AID,
)
from yubikit.openpgp import OpenPgpSession, KEY_REF, KdfNone, PW, INS, _INVALID_PIN
import logging

logger = logging.getLogger(__name__)


def safe_reset(connection: SmartCardConnection) -> None:
    """Performs an OpenPGP factory reset while avoiding any unneccessary commands.

    If any data is unreadable preventing the OpenPgpSession from initializing, then
    OpenPgpSession.reset() will not be able to be called. This function can instead
    be  used to reset the application into a fresh state.
    """
    logger.debug("Attempting safe OpenPGP factory reset")
    protocol = SmartCardProtocol(connection)
    protocol.select(AID.OPENPGP)

    for pw in (PW.USER, PW.ADMIN):
        logger.debug(f"Verify {pw.name} PIN with invalid attempts until blocked")
        while True:
            try:
                protocol.send_apdu(0, INS.VERIFY, 0, pw, _INVALID_PIN)
            except ApduError as e:
                if e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                    continue
                # Either blocked, or an unexpected error, move to the next step
                break

    # Reset the application
    logger.debug("Sending TERMINATE, then ACTIVATE")
    protocol.send_apdu(0, INS.TERMINATE, 0, 0)
    protocol.send_apdu(0, INS.ACTIVATE, 0, 0)
    logger.info("OpenPGP application data reset performed")


def get_openpgp_info(session: OpenPgpSession):
    """Get human readable information about the OpenPGP configuration.

    :param session: The OpenPGP session.
    """
    data = session.get_application_related_data()
    discretionary = data.discretionary
    retries = discretionary.pw_status
    info = {
        "OpenPGP version": "%d.%d" % data.aid.version,
        "Application version": "%d.%d.%d" % session.version,
        "PIN tries remaining": retries.attempts_user,
        "Reset code tries remaining": retries.attempts_reset,
        "Admin PIN tries remaining": retries.attempts_admin,
        "Require PIN for signature": retries.pin_policy_user,
        "KDF enabled": not isinstance(session.get_kdf(), KdfNone),
    }

    # Touch only available on YK4 and later
    if session.version >= (4, 2, 6):
        touch = {
            "Signature key": session.get_uif(KEY_REF.SIG),
            "Encryption key": session.get_uif(KEY_REF.DEC),
            "Authentication key": session.get_uif(KEY_REF.AUT),
        }
        if discretionary.attributes_att is not None:
            touch["Attestation key"] = session.get_uif(KEY_REF.ATT)
        info["Touch policies"] = touch

    return info
