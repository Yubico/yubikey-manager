# Copyright (c) 2016 Yubico AB
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

"""
Strings for YubiKey Manager

Note: String names must not start with underscore (_).
"""

organization = "Yubico"
domain = "yubico.com"
app_name = "YubiKey Manager"
win_title_1 = "YubiKey Manager (%s)"

no_key = "Insert a YubiKey..."
device = "Device"
serial_1 = "Serial: %s"
features = "Features"
connections = "Connections"
enabled = "Enabled"
disabled = "Disabled"
not_available = "Not available"
supported = "Supported"
configure_connections = "Configure connections"
remove_device = "Please remove and re-insert the device."
configure_protocols = "Configure enabled connection protocols"
configure_protocols_desc = "Set the enabled connection protocols for your YubiKey."
configure_protocols_reinsert = "Once changed, you will need to unplug and re-insert your YubiKey for the settings to take effect."
failed_configure_connections = "Failed to configure connections"
failed_configure_connections_desc = "There was a problem configuring the connections on the device.\n\nMake sure you do not have restricted access."
slot_configuration = "YubiKey slot configuration"
slot_1 = "Slot 1 (short press):"
slot_2 = "Slot 2 (long press):"
reading_state = "Reading state..."
previous = "Previous"
next_ = "Next"
overwrite_existing = "This will overwrite the existing configuration!"
warning = "WARNING"
deletes_content = "Permanently deletes the contents of this slot."
delete = "Delete"
erase_yubikey_slot = "Erase YubiKey slot {}"
erase_configuration = "Erasing configuration..."
configuration_erased = "Configuration erased!"
swap_slots = "Swap YubiKey slots"
swap_slots_desc = "Swaps the credentials between slots 1 and 2."
swap = "Swap credentials between slots"
writing_configuration = "Writing configuration..."
successfully_written = "Configuration successfully written!"
select_functionality = "Select the type of functionality to program:"
supports_variety_of_protocols = "The YubiKey supports a variety of protocols for the slot-based credentials."
yubikey_otp = "YubiKey OTP"
challenge_response = "Challenge-response"
static_password = "Static password"
oath_hotp = "OATH-HOTP"
configure_yubikey_slot = "Configure YubiKey slot {}"
program_otp_desc = "Programs a one-time-password credential using the YubiKey OTP protocol."
program_static_password_desc = "Stores a fixed password, which will be output each time you touch the button."
program_oath_hotp_desc = "Stores a numeric one-time-password using the OATH-HOTP standard."
program_challenge_resp_desc = "Programs an HMAC-SHA1 credential, which can be used for local authentication or encryption."
otp_desc = "When triggered, the YubiKey will output a one time password."
write_configuration = "Write configuration"
configure_yubikey_otp_slot = "Configure YubiKey OTP for slot {}"
secret_key = "Secret key:"
public_id = "Public ID:"
private_id = "Private ID:"
static_password_desc = "When triggered, the YubiKey will output a fixed password. To avoid problems with different keyboard layouts, the password should only contain modhex characters."
configure_static_password = "Configure static password for slot {}"
password_32_char = "Password, up to 32 characters."
password = "Password:"
keyboard_layout_note = "NOTE: Different keyboard layouts may render different passwords, especially for non-alphanumeric characters. To avoid this, choose a password consisting of modhex characters."
oath_hotp_desc = "When triggered, the YubiKey will output a HOTP code."
configure_hotp = "Configure HOTP credential for slot {}"
oath_secret = "OATH secret, in base32"
secret_key_base32 = "Secret key (base32):"
number_of_digits = "Number of digits:"
challenge_response_desc = "When queried, the YubiKey will respond to a challenge."
configure_challenge_resp = "Configure challenge-response for slot {}"
require_touch = "Require touch"
finish = "Finish"
failed_to_write = "Failed to write to the device.\nMake sure the device does not have restricted access."
configure_yubikey_slots = "Configure YubiKey slots"
use_serial = "Use serial number"
generate = "Generate"
configure = "Configure"
erase = "Erase"
configured = "Configured"
blank = "Blank"
close = "Close"
multiple_keys = "Multiple YubiKeys detected.\nOnly a single YubiKey at a time is supported."
busy_key = "The YubiKey seems busy. Try re-inserting it."
