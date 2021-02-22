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

import click

"""
Command line aliases to support commands which have moved.
"""


ignore = None


def replace(*args):
    def inner(argv, alias, match_at):
        return argv[:match_at] + list(args) + argv[match_at + len(alias) :]

    return inner


def oath_access_remember(argv, alias, match_at):
    args = ["oath", "access"]
    for flag in ("-c", "--clear-all"):
        if flag in argv:
            argv.remove(flag)
            args.extend(["forget", "--all"])
            break
    else:
        for flag in ("-F", "--forget"):
            if flag in argv:
                argv.remove(flag)
                args.append("forget")
                break
        else:
            args.append("remember")
    argv = argv[:match_at] + args + argv[match_at + len(alias) :]
    return argv


_aliases = (
    (["config", "mode"], ignore),  # Avoid match on next line
    (["mode"], replace("config", "mode")),
    (["fido", "delete"], replace("fido", "credentials", "delete")),
    (["fido", "list"], replace("fido", "credentials", "list")),
    (["fido", "set-pin"], replace("fido", "access", "change-pin")),
    (["fido", "unlock"], replace("fido", "access", "verify-pin")),
    (["piv", "change-pin"], replace("piv", "access", "change-pin")),
    (["piv", "change-puk"], replace("piv", "access", "change-puk")),
    (
        ["piv", "change-management-key"],
        replace("piv", "access", "change-management-key"),
    ),
    (["piv", "set-pin-retries"], replace("piv", "access", "set-retries")),
    (["piv", "unblock-pin"], replace("piv", "access", "unblock-pin")),
    (["piv", "attest"], replace("piv", "keys", "attest")),
    (["piv", "import-key"], replace("piv", "keys", "import")),
    (["piv", "generate-key"], replace("piv", "keys", "generate")),
    (["piv", "import-certificate"], replace("piv", "certificates", "import")),
    (["piv", "export-certificate"], replace("piv", "certificates", "export")),
    (["piv", "generate-certificate"], replace("piv", "certificates", "generate")),
    (["piv", "delete-certificate"], replace("piv", "certificates", "delete")),
    (["piv", "generate-csr"], replace("piv", "certificates", "request")),
    (["piv", "read-object"], replace("piv", "objects", "export")),
    (["piv", "write-object"], replace("piv", "objects", "import")),
    (["piv", "set-chuid"], replace("piv", "objects", "generate", "chuid")),
    (["piv", "set-ccc"], replace("piv", "objects", "generate", "ccc")),
    (["openpgp", "set-pin-retries"], replace("openpgp", "access", "set-retries")),
    (["openpgp", "import-certificate"], replace("openpgp", "certificates", "import")),
    (["openpgp", "export-certificate"], replace("openpgp", "certificates", "export")),
    (["openpgp", "delete-certificate"], replace("openpgp", "certificates", "delete")),
    (["openpgp", "attest"], replace("openpgp", "keys", "attest")),
    (
        ["openpgp", "import-attestation-key"],
        replace("openpgp", "keys", "import", "att"),
    ),
    (["openpgp", "set-touch"], replace("openpgp", "keys", "set-touch")),
    (["oath", "add"], replace("oath", "accounts", "add")),
    (["oath", "code"], replace("oath", "accounts", "code")),
    (["oath", "delete"], replace("oath", "accounts", "delete")),
    (["oath", "list"], replace("oath", "accounts", "list")),
    (["oath", "uri"], replace("oath", "accounts", "uri")),
    (["oath", "set-password"], replace("oath", "access", "change")),
    (["oath", "remember-password"], oath_access_remember),
)


def _find_match(data, selection):
    ln = len(selection)
    for i in range(0, len(data) - ln + 1):
        if data[i : i + ln] == selection:
            return i


def apply_aliases(argv):
    for (alias, f) in _aliases:
        i = _find_match(argv, alias)
        if i is not None:
            if f:
                argv = f(argv, alias, i)
                click.echo(
                    "WARNING: "
                    "The use of this command is deprecated and will be removed!\n"
                    "Replace with: ykman " + " ".join(argv[1:]) + "\n",
                    err=True,
                )
            break  # Only handle first match
    return argv
