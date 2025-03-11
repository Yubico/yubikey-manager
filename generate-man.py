#!/usr/bin/env python3

import re
import sys
from subprocess import check_output  # nosec
from typing import List

if len(sys.argv) != 4:
    print("Usage: generate-man.py <version> <year> <month>")
    sys.exit(1)

version, year, month = sys.argv[1:]
int(year)
month = month[0].upper() + month[1:].lower()

print(
    rf""".TH YKMAN "1" "{month} {year}" "ykman {version}" "User Commands"
.SH NAME
ykman \- YubiKey Manager (ykman)
.SH SYNOPSIS
.B ykman
[\fI\,OPTIONS\/\fR] \fI\,COMMAND \/\fR[\fI\,ARGS\/\fR]..."""
)

help_text = check_output(["poetry", "run", "ykman", "--help"]).decode()  # nosec
parts = re.split(r"\b[A-Z][a-z]+:\s+", help_text)
description = re.split(r"\s{2,}", parts[1])[1].strip()

print(f".SH DESCRIPTION\n.PP\n{description}\n.SH OPTIONS")

opt: List[str] = []
options = parts[3].strip().split("\n  ")
while options:
    o = options.pop(0)
    if o.startswith("-"):
        if opt:
            print(" ".join(opt))
            opt = []
        print(".TP")
        oo = re.split(r"\s{2,}", o)
        print(re.sub(r"([-a-z]+)", r"\\fB\1\\fR", oo.pop(0)).replace("-", r"\-"))
        if oo:
            options = oo + options
    else:
        opt.append(o.strip())

if opt:
    print(" ".join(opt))

print('.SS "Commands:"')
commands = re.split(r"\s{2,}", parts[4].strip())
while commands:
    print(f".TP\n{commands.pop(0)}\n{commands.pop(0)}")

print(".SH EXAMPLES")
examples = re.split(r"\s{2,}", parts[2].strip())
while examples:
    print(f".PP\n{examples.pop(0)}\n.PP\n{examples.pop(0)}")

print(
    """.SH SHELL COMPLETION
.PP
Experimental shell completion for the command line tool is available.
To enable it, run this command once (for Bash):
.PP
$ source <(_YKMAN_COMPLETE=bash_source ykman | sudo tee /etc/bash_completion.d/ykman)
.PP
More information on shell completion (including instructions for other shells) is
available at:
https://click.palletsprojects.com/en/stable/shell-completion/"""
)
