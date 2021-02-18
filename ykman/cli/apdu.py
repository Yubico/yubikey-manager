# Copyright (c) 2020 Yubico AB
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

from binascii import a2b_hex
from yubikit.core import AID
from yubikit.core.smartcard import SmartCardConnection, SmartCardProtocol, ApduError, SW
from .util import EnumChoice, ykman_command

import re
import sys
import click
import struct
import logging


logger = logging.getLogger(__name__)


APDU_PATTERN = re.compile(
    r"^"
    r"(?P<cla>[0-9a-f]{2})?(?P<ins>[0-9a-f]{2})(?P<params>[0-9a-f]{4})?"
    r"(?::(?P<body>(?:[0-9a-f]{2})+))?"
    r"(?P<check>=(?P<sw>[0-9a-f]{4})?)?"
    r"$",
    re.IGNORECASE,
)


def _hex(data):
    return " ".join(f"{d:02X}" for d in data)


def _parse_apdu(data):
    m = APDU_PATTERN.match(data)
    if not m:
        raise ValueError("Invalid APDU format: " + data)
    cla = int(m.group("cla") or "00", 16)
    ins = int(m.group("ins"), 16)
    params = int(m.group("params") or "0000", 16)
    body = a2b_hex(m.group("body") or "")
    if m.group("check"):
        sw = int(m.group("sw") or "9000", 16)
    else:
        sw = None
    p1, p2 = params >> 8, params & 0xFF
    return (cla, ins, p1, p2, body), sw


def _print_response(resp, sw, no_pretty):
    click.echo(f"RECV (SW={sw:04X})" + (":" if resp else ""))
    if no_pretty:
        click.echo(resp.hex().upper())
    else:
        for i in range(0, len(resp), 16):
            chunk = resp[i : i + 16]
            click.echo(
                " ".join(f"{c:02X}" for c in chunk).ljust(50)
                # Replace non-printable characters with a dot.
                + "".join(chr(c) if 31 < c < 127 else chr(183) for c in chunk)
            )


@ykman_command(SmartCardConnection, hidden="--full-help" not in sys.argv)
@click.pass_context
@click.option(
    "-x", "--no-pretty", is_flag=True, help="Print only the hex output of a response"
)
@click.option(
    "-a", "--app", type=EnumChoice(AID), required=False, help="Select application",
)
@click.argument("apdu", nargs=-1)
@click.option("-s", "--send-apdu", multiple=True, help="Provide full APDUs")
def apdu(ctx, no_pretty, app, apdu, send_apdu):
    """
    Execute arbitary APDUs.
    Provide APDUs as a hex encoded, space-separated list using the following syntax:
    [CLA]INS[P1P2][:DATA][=EXPECTED_SW]

    If not provided CLA, P1 and P2 are all set to zero.
    Setting EXPECTED_SW will cause the command to check the response SW an fail if it
    differs. "=" can be used as shorthand for "=9000" (SW=OK).

    Examples:

    \b
      Select the OATH application, send a LIST instruction (0xA1), and make sure we get
      sw=9000 (these are equivalent):
      $ ykman apdu a40400:a000000527210101=9000 a1=9000
        or
      $ ykman apdu -a oath a1=

    \b
      Factory reset the OATH application:
      $ ykman apdu -a oath 04dead
        or
      $ ykman apdu a40400:a000000527210101 04dead
        or (using full-apdu mode)
      $ ykman apdu -s 00a4040008a000000527210101 -s 0004dead
    """
    if apdu and send_apdu:
        ctx.fail("Cannot mix positional APDUs and -s/--send-apdu.")
    elif not send_apdu:
        apdus = [_parse_apdu(data) for data in apdu]
        if not apdus and not app:
            ctx.fail("No commands provided.")

    protocol = SmartCardProtocol(ctx.obj["conn"])
    is_first = True

    if app:
        is_first = False
        click.echo("SELECT AID: " + _hex(app))
        resp = protocol.select(app)
        _print_response(resp, SW.OK, no_pretty)

    if send_apdu:  # Compatibility mode (full APDUs)
        for apdu in send_apdu:
            if not is_first:
                click.echo()
            else:
                is_first = False
            apdu = a2b_hex(apdu)
            click.echo("SEND: " + _hex(apdu))
            resp, sw = protocol.connection.send_and_receive(apdu)
            _print_response(resp, sw, no_pretty)
    else:  # Standard mode
        for apdu, check in apdus:
            if not is_first:
                click.echo()
            else:
                is_first = False
            header, body = apdu[:4], apdu[4]
            req = _hex(struct.pack(">BBBB", *header))
            if body:
                req += " -- " + _hex(body)
            click.echo("SEND: " + req)
            try:
                resp = protocol.send_apdu(*apdu)
                sw = SW.OK
            except ApduError as e:
                resp = e.data
                sw = e.sw
            _print_response(resp, sw, no_pretty)

            if check is not None and sw != check:
                click.echo(f"Aborted due to error (expected SW={check:04X}).")
                ctx.exit(1)
