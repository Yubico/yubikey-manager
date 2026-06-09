# Build MSI installer for YubiKey Manager CLI.
#
# Expects target/release/ykman.exe and target/release/ykman-svc.exe to exist
# (run `cargo build --release -p ykman-cli -p ykman-svc` first).
#
# Usage: Run from the repository root.

$ErrorActionPreference = "Stop"

$CWD = Get-Location
$REPO_ROOT = $CWD
$BINARY_DIR = "$REPO_ROOT\target\release"
$SCRIPT_DIR = $PSScriptRoot

# Verify binaries exist
if (-not (Test-Path "$BINARY_DIR\ykman.exe")) {
    Write-Error "ykman.exe not found in $BINARY_DIR"
    exit 1
}
if (-not (Test-Path "$BINARY_DIR\ykman-svc.exe")) {
    Write-Error "ykman-svc.exe not found in $BINARY_DIR"
    exit 1
}

$VERSION = $(& "$BINARY_DIR\ykman.exe" --version).Split(' ')[-1]
echo "Release version: $VERSION"

# WiX needs a 4-part version (major.minor.patch.build)
$SIMPLE_VERSION = "$($VERSION.Split('-')[0]).0"
echo "MSI version: $SIMPLE_VERSION"

# Generate .wxs from template
$WXS_CONTENT = (Get-Content -path "$SCRIPT_DIR\ykman.wxs.in" -Raw)
$WXS_CONTENT = $WXS_CONTENT -replace '\{RELEASE_VERSION\}', $SIMPLE_VERSION
$WXS_CONTENT = $WXS_CONTENT -replace '\{BINARY_DIR\}', $BINARY_DIR
$WXS_CONTENT | Set-Content -Path "$SCRIPT_DIR\ykman.wxs"

$WIX_BIN = "$env:WIX\bin"

echo "Running candle..."
& "$WIX_BIN\candle.exe" "$SCRIPT_DIR\ykman.wxs" -ext WixUtilExtension -arch x64 -out "$SCRIPT_DIR\ykman.wixobj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

echo "Running light..."
& "$WIX_BIN\light.exe" "$SCRIPT_DIR\ykman.wixobj" -ext WixUIExtension -ext WixUtilExtension -o "$CWD\ykman.msi"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

echo "MSI created: $CWD\ykman.msi"

# Cleanup intermediate files
Remove-Item -ErrorAction SilentlyContinue "$SCRIPT_DIR\ykman.wxs"
Remove-Item -ErrorAction SilentlyContinue "$SCRIPT_DIR\ykman.wixobj"
Remove-Item -ErrorAction SilentlyContinue "$CWD\ykman.wixpdb"

