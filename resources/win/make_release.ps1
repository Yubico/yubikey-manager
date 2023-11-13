# Set-PSDebug -Trace 1

$ErrorActionPreference = "Stop"

$CWD = pwd
$SOURCE_DIR = "$CWD\ykman"

echo "Signing ykman.exe"
signtool.exe sign /sha1 DD86A2E1383B0E4E1C823B606DDBBCC26E1FF82D /fd SHA256 /t http://timestamp.digicert.com "$SOURCE_DIR\ykman.exe"

$VERSION = $(& "$SOURCE_DIR\ykman.exe" --version).Split(' ')[-1]

& $PSScriptRoot\make_msi.ps1

echo "Signing .msi"
$OUTPUT_FILE = "yubikey-manager-$VERSION-win64.msi"
mv ".\ykman.msi" $OUTPUT_FILE

signtool.exe sign /sha1 DD86A2E1383B0E4E1C823B606DDBBCC26E1FF82D /fd SHA256 /t http://timestamp.digicert.com /d "YubiKey Manager CLI" ".\$OUTPUT_FILE"

echo "Installer signed: $OUTPUT_FILE"
