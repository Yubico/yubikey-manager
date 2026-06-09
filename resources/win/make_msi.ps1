# Build MSI installer for YubiKey Manager CLI.
#
# Usage: .\make_msi.ps1 [-SourceDir <path>]
#
# SourceDir should contain ykman.exe and ykman-svc.exe.
# Defaults to the current working directory.

param(
    [string]$SourceDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$SourceDir = (Resolve-Path $SourceDir).Path
$SCRIPT_DIR = $PSScriptRoot

# Verify binaries exist
if (-not (Test-Path "$SourceDir\ykman.exe")) {
    Write-Error "ykman.exe not found in $SourceDir"
    exit 1
}
if (-not (Test-Path "$SourceDir\ykman-svc.exe")) {
    Write-Error "ykman-svc.exe not found in $SourceDir"
    exit 1
}

$VERSION = $(& "$SourceDir\ykman.exe" --version).Split(' ')[-1]
echo "Release version: $VERSION"
echo "Source: $SourceDir"

# WiX needs a 4-part version (major.minor.patch.build)
$SIMPLE_VERSION = "$($VERSION.Split('-')[0]).0"
echo "MSI version: $SIMPLE_VERSION"

# Generate .wxs from template
$WXS_CONTENT = (Get-Content -path "$SCRIPT_DIR\ykman.wxs.in" -Raw)
$WXS_CONTENT = $WXS_CONTENT -replace '\{RELEASE_VERSION\}', $SIMPLE_VERSION
$WXS_CONTENT = $WXS_CONTENT -replace '\{BINARY_DIR\}', $SourceDir
$WXS_CONTENT | Set-Content -Path "$SCRIPT_DIR\ykman.wxs"

$WIX_BIN = "$env:WIX\bin"

echo "Running candle..."
& "$WIX_BIN\candle.exe" "$SCRIPT_DIR\ykman.wxs" -ext WixUtilExtension -arch x64 -out "$SCRIPT_DIR\ykman.wixobj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

echo "Running light..."
$CWD = (Get-Location).Path
$OUTPUT = "$CWD\ykman.msi"
& "$WIX_BIN\light.exe" "$SCRIPT_DIR\ykman.wixobj" -ext WixUIExtension -ext WixUtilExtension -o $OUTPUT
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

echo "MSI created: $OUTPUT"

# Cleanup intermediate files
Remove-Item -ErrorAction SilentlyContinue "$SCRIPT_DIR\ykman.wxs"
Remove-Item -ErrorAction SilentlyContinue "$SCRIPT_DIR\ykman.wixobj"
Remove-Item -ErrorAction SilentlyContinue "$CWD\ykman.wixpdb"

