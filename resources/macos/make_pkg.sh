#!/bin/bash
# Script to produce an OS X installer .pkg

set -e

CWD=`pwd`
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SOURCE_DIR="$CWD/ykman"
RELEASE_VERSION=`$SOURCE_DIR/ykman --version | awk '{print $(NF)}'`

if [ -z "$1" ]
then
	PKG="ykman.pkg"
else
	PKG="$1"
fi

echo "Release version : $RELEASE_VERSION"
echo "Binaries: $SOURCE_DIR"

set -x

cd $SCRIPT_DIR

# Ensure executable, since we may have unpacked from zip
chmod +x pkg_scripts/*

mkdir -p pkg/root/usr/local/bin pkg/comp
cp -R $SOURCE_DIR pkg/root/usr/local/

# Create a symlink to the main binary that is on the PATH
(cd pkg/root/usr/local/bin && ln -s ../ykman/ykman)

pkgbuild --root="pkg/root" --scripts="pkg_scripts" --identifier "com.yubico.yubikey-manager" --version "$RELEASE_VERSION" "pkg/comp/ykman.pkg"

productbuild  --package-path "pkg/comp" --distribution "distribution.xml" "$PKG"

# Move to dist
mv $PKG $CWD/$PKG

# Clean up
rm -rf pkg
