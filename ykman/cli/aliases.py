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

import sys
import click

"""
Command line aliases to support commands which have moved.
"""

_aliases = (
    (["mode"], ["config", "mode"]),
    (["fido", "delete"], ["fido", "credentials", "delete"]),
    (["fido", "list"], ["fido", "credentials", "list"]),
    (["fido", "set-pin"], ["fido", "access", "change-pin"]),
    (["fido", "unlock"], ["fido", "access", "unlock"]),
    (["piv", "change-pin"], ["piv", "access", "change-pin"]),
    (["piv", "change-puk"], ["piv", "access", "change-puk"]),
    (["piv", "change-management-key"], ["piv", "access", "change-management-key"]),
    (["piv", "set-pin-retries"], ["piv", "access", "set-retries"]),
    (["piv", "unblock-pin"], ["piv", "access", "unblock-pin"]),
    (["piv", "attest"], ["piv", "keys", "attest"]),
    (["piv", "import-key"], ["piv", "keys", "import"]),
    (["piv", "generate-key"], ["piv", "keys", "generate"]),
    (["piv", "import-certificate"], ["piv", "certificates", "import"]),
    (["piv", "export-certificate"], ["piv", "certificates", "export"]),
    (["piv", "generate-certificate"], ["piv", "certificates", "generate"]),
    (["piv", "delete-certificate"], ["piv", "certificates", "delete"]),
    (["piv", "generate-csr"], ["piv", "certificates", "request"]),
    (["piv", "read-object"], ["piv", "objects", "export"]),
    (["piv", "write-object"], ["piv", "objects", "import"]),
    (["piv", "set-chuid"], ["piv", "objects", "generate", "chuid"]),
    (["piv", "set-ccc"], ["piv", "objects", "generate", "ccc"]),
    (["openpgp", "set-pin-retries"], ["openpgp", "access", "set-retries"]),
    (["openpgp", "import-certificate"], ["openpgp", "certificates", "import"]),
    (["openpgp", "export-certificate"], ["openpgp", "certificates", "export"]),
    (["openpgp", "delete-certificate"], ["openpgp", "certificates", "delete"]),
    (["openpgp", "attest"], ["openpgp", "keys", "attest"]),
    (["openpgp", "import-attestation-key"], ["openpgp", "keys", "import", "att"]),
    (["openpgp", "set-touch"], ["openpgp", "keys", "set-touch"]),
)


def _find_match(data, selection):
    ln = len(selection)
    for i in range(0, len(data) - ln + 1):
        if data[i : i + ln] == selection:
            return i


def apply_aliases():
    for (alias, replacement) in _aliases:
        i = _find_match(sys.argv, alias)
        if i is not None:
            sys.argv = sys.argv[:i] + replacement + sys.argv[i + len(alias) :]
            click.echo(
                "WARNING: The use of this command is deprecated and will be removed!\n"
                "Replace with: ykman " + " ".join(sys.argv[1:]) + "\n",
                err=True,
            )
            return
