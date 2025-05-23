# Set-PSDebug -Trace 1

$ErrorActionPreference = "Stop"

$CWD = pwd
$SOURCE_DIR = "$CWD\ykman"

echo "Signing ykman.exe"
signtool.exe sign /sha1 a1614cd84976030d49209b56162d9efa69b73698 /fd SHA256 /t http://timestamp.digicert.com "$SOURCE_DIR\ykman.exe"

$VERSION = $(& "$SOURCE_DIR\ykman.exe" --version).Split(' ')[-1]

& $PSScriptRoot\make_msi.ps1

echo "Signing .msi"
$OUTPUT_FILE = "yubikey-manager-$VERSION-win64.msi"
mv ".\ykman.msi" $OUTPUT_FILE

signtool.exe sign /sha1 a1614cd84976030d49209b56162d9efa69b73698 /fd SHA256 /t http://timestamp.digicert.com /d "YubiKey Manager CLI" ".\$OUTPUT_FILE"

echo "Installer signed: $OUTPUT_FILE"
