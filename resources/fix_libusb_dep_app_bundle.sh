#!/bin/sh

# When building an .app bundle, libusb is in one folder to deep.
# This moves the lib up one level.

set -e
mv YubiKey\ Manager.app/Contents/MacOS/libusb-1.0.dylib/ YubiKey\ Manager.app/Contents/MacOS/libusb-1.0.dylib.bak
cp YubiKey\ Manager.app/Contents/MacOS/libusb-1.0.dylib.bak/libusb-1.0.dylib YubiKey\ Manager.app/Contents/MacOS/libusb-1.0.dylib
rm -rf dist/YubiKey\ Manager.app/Contents/MacOS/libusb-1.0.dylib.bak/
echo "Fixed libusb path in Yubikey Manager.app"


