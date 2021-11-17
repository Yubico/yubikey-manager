#!/bin/bash
# Script to produce an OS X installer .pkg

if [ "$#" -lt 1 ]; then
    echo ""
    echo "      Usage: ./make_installer.sh <Release version> [<binary directory>]"
    echo ""
    exit 0
fi

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

RELEASE_VERSION=$1

if [ -z "$2" ]
then
    SOURCE_DIR="$SCRIPT_DIR/../../dist/ykman"
else
    SOURCE_DIR=$2
    if [[ ! "$SOURCE_DIR" = /* ]]; then
        SOURCE_DIR=`pwd`/$SOURCE_DIR
    fi
fi


echo "Release version : $RELEASE_VERSION"
echo "Binaries: $SOURCE_DIR"

set -x

cd $SCRIPT_DIR

# Create needed directories
mkdir -p pkg/root/usr/local/bin pkg/comp ../../dist
cp -r $SOURCE_DIR pkg/root/usr/local/

# Make sure binary is executable
BIN="pkg/root/usr/loca/ykman/ykman"
if [[ ! -x "$BIN" ]]; then
  chmod +x "$BIN"
fi

# Create symlink in /usr/local/bin
(cd pkg/root/usr/local/bin && ln -s ../ykman/ykman)

pkgbuild --root="pkg/root" --identifier "com.yubico.yubikey-manager" --version "$RELEASE_VERSION" "pkg/comp/ykman.pkg"

productbuild  --package-path "pkg/comp" --distribution "distribution.xml" "ykman.pkg"

# Move to dist
mv ykman.pkg ../../dist/ykman-$RELEASE_VERSION.pkg

# Clean up
rm -rf pkg
