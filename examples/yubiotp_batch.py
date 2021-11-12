"""
This script will program Yubico OTP credentials for a batch of YubiKeys, outputting
a .ycfg file with the secret values for upload to a validation server.

YubiKeys are inserted as the script is running, and can be removed once programmed.
When done, press Ctrl+C to end the batch. If a YubiKey is inserted twice in the same
session it will be ignored.

Usage: okta.py <output_file>
"""

from ykman import scripting as s
from ykman.otp import format_csv
from yubikit.yubiotp import YubiOtpSession, YubiOtpSlotConfiguration, SLOT

import os
import sys
import struct


# ycfg file out output to, given as an argument
output_fname = sys.argv[1]

# Write configuration to file
with open(output_fname, "a") as output:
    for device in s.multi(allow_initial=True):
        print(f"Programming YubiKey: {device}...")
        serial = device.info.serial
        if serial is None:
            print("No serial number, skipping")
            continue

        with device.otp() as connection:
            session = YubiOtpSession(connection)

            # Change these as appropriate
            # slot = SLOT.ONE
            slot = SLOT.TWO

            # "cccc" + serial, 6 bytes (12 characters in modhex)
            public_id = b"\x00\x00" + struct.pack(b">I", serial)

            # Randomly generate private ID and AES key
            private_id = os.urandom(6)
            key = os.urandom(16)

            # Access code from serial (BCD encoded, 6 bytes)
            # access_code = bytes.fromhex(f"{serial:012}")
            access_code = None

            # Write the configuration to the YubiKey
            session.put_configuration(
                slot,
                YubiOtpSlotConfiguration(public_id, private_id, key).append_cr(True),
                access_code,
            )

            # Write the configuration as a line in the output file
            csv_line = format_csv(serial, public_id, private_id, key, access_code)
            output.write(csv_line + "\n")

        print("Done! Insert next YubiKey...")

print("Done programming. Output written to:", output_fname)
