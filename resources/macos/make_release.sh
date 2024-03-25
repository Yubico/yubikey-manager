#!/bin/bash
# Script to produce a signed OS X installer .pkg

set -e

if [ "$#" -lt 2 ]; then
    echo ""
    echo "      Usage: ./make_release.sh <apple_account> <apple_password>"
    echo ""
    exit 0
fi

CWD=`pwd`
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Script dir: $SCRIPT_DIR"

SOURCE_DIR="$CWD/ykman"

# Ensure executable, since we may have unpacked from zip
chmod +x $SOURCE_DIR/ykman

# Remove Python framework directory as it isn't needed
rm -rf $SOURCE_DIR/_internal/Python.framework

RELEASE_VERSION=`$SOURCE_DIR/ykman --version | awk '{print $(NF)}'`
PKG="yubikey-manager-$RELEASE_VERSION-mac.pkg"

echo "This will sign and notarize the app. Please make sure you have the code signing YubiKey connected."
echo ""
echo "Release version: $RELEASE_VERSION"
echo "Binaries: $SOURCE_DIR"
echo "Apple user ID for notarization: $1"
echo ""
read -p "Press enter to continue..."

# Sign binaries
codesign -f --timestamp --options runtime --entitlements $SCRIPT_DIR/ykman.entitlements --sign 'Application' $SOURCE_DIR/ykman
codesign -f --timestamp --options runtime --sign 'Application' $(find $SOURCE_DIR/_internal -name "*.dylib" -o -name "*.so")
codesign -f --timestamp --options runtime --sign 'Application' $SOURCE_DIR/_internal/Python

# Build pkg
sh $SCRIPT_DIR/make_pkg.sh ykman-unsigned.pkg

# Sign the installer
productsign --sign 'Installer' ykman-unsigned.pkg $PKG

# Clean up
rm ykman-unsigned.pkg

echo "Installer signed, submitting for Notarization..."

# Notarize
STATUS=$(xcrun notarytool submit "$PKG" --apple-id $1 --team-id LQA3CS5MM7 --password $2 --wait)
echo "Notarization status: ${STATUS}"

if [[ "$STATUS" == *"Accepted"* ]]; then
	echo "Notarization successful. Staple the .pkg"
	xcrun stapler staple -v "$PKG"

	echo "# .pkg stapled. Everything should be ready for release!"
fi
