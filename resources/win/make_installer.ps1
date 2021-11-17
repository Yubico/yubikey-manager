# Set-PSDebug -Trace 1


$RELEASE_VERSION=$args[0] # Release version
$CWD=pwd
if(!($args[1])) {
  $SOURCE_DIR="$PSScriptRoot/../../dist/ykman/"
} else {
  $SOURCE_DIR="$CWD/$($args[1])" # Location of binary files
}

echo "Release version : $RELEASE_VERSION"
echo "Binaries: $SOURCE_DIR"

cd $PSScriptRoot

((Get-Content -path ykman.wxs.in -Raw) -replace '{RELEASE_VERSION}',$RELEASE_VERSION) | Set-Content -Path ykman.wxs

$env:SRCDIR = $SOURCE_DIR
& "$env:WIX\bin\heat.exe" dir $SOURCE_DIR -out fragment.wxs -gg -scom -srd -sfrag -sreg -dr INSTALLDIR -cg ApplicationFiles -var env.SRCDIR
& "$env:WIX\bin\candle.exe" fragment.wxs "ykman.wxs" -ext WixUtilExtension  -arch "x64"
& "$env:WIX\bin\light.exe" -v fragment.wixobj "ykman.wixobj" -ext WixUIExtension -ext WixUtilExtension -o "ykman.msi"

# Move to dist
$OUTPUT="../../dist/ykman-$RELEASE_VERSION.msi"
if (Test-Path $OUTPUT) {
  Remove-Item $OUTPUT
}
mv ykman.msi $OUTPUT

# Cleanup
rm fragment.wxs
rm fragment.wixobj
rm ykman.wxs
rm ykman.wixobj
rm ykman.wixpdb

cd $CWD
