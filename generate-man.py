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

help_text = check_output(["poetry", "run", "ykman", "--help"]).decode()
parts = re.split(r"\b[A-Z][a-z]+:\s+", help_text)
description = re.split(r"\s{2,}", parts[1])[1].strip()

print(f".SH DESCRIPTION\n.PP\n{description}\n.SH OPTIONS")

options = re.split(r"\s{2,}", parts[3].strip())
buf = ""
opt: List[str] = []
while options:
    o = options.pop(0)
    if o.startswith("-"):
        if opt:
            print(".TP")
            print((opt[0] + "\n" + " ".join(opt[1:])).replace("-", r"\-"))
        opt = [re.sub(r"([-a-z]+)", r"\\fB\1\\fR", o)]
    else:
        opt.append(o)
print(".TP")
print((opt[0] + "\n" + " ".join(opt[1:])).replace("-", r"\-"))

print('.SS "Commands:"')
commands = re.split(r"\s{2,}", parts[4].strip())
while commands:
    print(f".TP\n{commands.pop(0)}\n{commands.pop(0)}")

print(".SH EXAMPLES")
examples = re.split(r"\s{2,}", parts[2].strip())
while examples:
    print(f".PP\n{examples.pop(0)}\n.PP\n{examples.pop(0)}")
