# Build MSI installer for YubiKey Manager CLI.
#
# Usage: .\make_msi.ps1 [-SourceDir <path>] [-Architecture x64|arm64] [-WixBin <path>]
#
# SourceDir should contain ykman.exe and ykman-svc.exe.
# Defaults to the current working directory.

param(
    [string]$SourceDir = (Get-Location).Path,
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64',
    [string]$WixBin = "$env:WIX\bin"
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
$WXS_CONTENT = $WXS_CONTENT -replace '\{ARCHITECTURE\}', $Architecture
$INSTALLER_VERSION = if ($Architecture -eq 'arm64') { '500' } else { '301' }
$WXS_CONTENT = $WXS_CONTENT -replace '\{INSTALLER_VERSION\}', $INSTALLER_VERSION
# Different binaries at the same install paths must not share component GUIDs.
$COMPONENT_GUIDS = if ($Architecture -eq 'arm64') {
    @{
        ENVVARS_GUID = '0bf71425-4599-5048-a9ff-440cc59e98fd'
        YKMAN_EXE_GUID = '114efd2a-4f7f-5c41-acdd-fba70fc1e709'
        YKMAN_SVC_GUID = '085d53ef-8e28-5d07-82c8-fcf8a7ce74bd'
        SHORTCUT_GUID = '16c88500-b08b-52f7-9a0d-27b28f31c1bf'
    }
} else {
    @{
        ENVVARS_GUID = '7e30efe4-dc8b-40ba-a182-76e490de4f37'
        YKMAN_EXE_GUID = 'a3d7c1e2-5f8a-4b9e-9c1d-2e4f6a8b0c3d'
        YKMAN_SVC_GUID = 'b4e8d2f3-6a9b-4c0f-ad2e-3f5a7b9c1d4e'
        SHORTCUT_GUID = 'fba0ab59-48d1-4050-82eb-acad31cf2239'
    }
}
foreach ($name in $COMPONENT_GUIDS.Keys) {
    $WXS_CONTENT = $WXS_CONTENT.Replace("{$name}", $COMPONENT_GUIDS[$name])
}
$WXS_CONTENT | Set-Content -Path "$SCRIPT_DIR\ykman.wxs"

if (-not (Test-Path "$WixBin\candle.exe") -or -not (Test-Path "$WixBin\light.exe")) {
    throw "WiX candle.exe and light.exe not found in $WixBin"
}

echo "Running candle..."
& "$WixBin\candle.exe" "$SCRIPT_DIR\ykman.wxs" -ext WixUtilExtension -arch $Architecture -out "$SCRIPT_DIR\ykman.wixobj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

echo "Running light..."
$CWD = (Get-Location).Path
$OUTPUT = if ($Architecture -eq 'arm64') { "$CWD\ykman-arm64.msi" } else { "$CWD\ykman.msi" }
& "$WixBin\light.exe" "$SCRIPT_DIR\ykman.wixobj" -ext WixUIExtension -ext WixUtilExtension -o $OUTPUT
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

echo "MSI created: $OUTPUT"

# Cleanup intermediate files
Remove-Item -ErrorAction SilentlyContinue "$SCRIPT_DIR\ykman.wxs"
Remove-Item -ErrorAction SilentlyContinue "$SCRIPT_DIR\ykman.wixobj"
Remove-Item -ErrorAction SilentlyContinue "$CWD\ykman.wixpdb"
