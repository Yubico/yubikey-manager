"""
This script will program Yubico OTP credentials for a batch of YubiKeys, outputting
a .csv file with the secret values for upload to a validation server.

YubiKeys are programmed over NFC using an NFC reader. One YubiKey can be placed
on the reader at a time. When done, press Ctrl+C to end the batch. If a YubiKey
is presented twice in the same session it will be ignored.

Usage: yubiotp_batch_nfc.py <nfc_reader> <output_file>
"""

import os
import struct
import sys

from ykman import scripting as s
from ykman.otp import format_csv
from yubikit.yubiotp import SLOT, YubiOtpSession, YubiOtpSlotConfiguration

try:
    # name of the NFC reader to use. Case-insensitive substring matching.
    nfc_reader = sys.argv[1]  # e.g: "hid"
    # csv file out output to, given as an argument
    output_fname = sys.argv[2]  # e.g: "output.csv"
except IndexError:
    print("USAGE: yubiotp_batch_nfc.py <NFC_READER> <OUTPUT_FILE>")
    sys.exit(1)

# Write configuration to file
with open(output_fname, "a") as output:
    # Look for YubiKeys on the NFC reader matched by the argument
    for device in s.multi_nfc(nfc_reader):
        print(f"Programming YubiKey: {device}...")
        serial = device.info.serial
        if serial is None:
            print("No serial number, skipping")
            continue

        # NFC uses a SmartCardConnection for the OTP application
        with device.smart_card() as connection:
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

        print("Done! Replace the YubiKey with the next one...")

print("Done programming. Output written to:", output_fname)
