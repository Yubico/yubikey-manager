param(
  [string]$Arch = "x64"   # Accepts x64 or arm64
)

# WiX 5 build script for ykman.msi (multi-arch capable)

$ErrorActionPreference = "Stop"

function Fail($msg) {
    Write-Error $msg
    exit 1
}

if ($Arch -notin @("x64","arm64")) {
    Fail "Unsupported architecture '$Arch'. Use x64 or arm64."
}

$CWD = Get-Location
$SOURCE_DIR = Join-Path $CWD "ykman"

if (-not (Test-Path (Join-Path $SOURCE_DIR "ykman.exe"))) {
    Fail "ykman.exe not found in $SOURCE_DIR. Ensure PyInstaller step produced the binary for $Arch."
}

$rawVersion = & "$SOURCE_DIR\ykman.exe" --version
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rawVersion)) {
    Fail "Failed to obtain version from ykman.exe."
}
$baseVersion = ($rawVersion.Split(' ')[-1])
$SIMPLE_VERSION = "$(($baseVersion.Split('-')[0])).0"

Write-Host "Raw version: $baseVersion"
Write-Host "MSI ProductVersion: $SIMPLE_VERSION"
Write-Host "Architecture: $Arch"
Write-Host "Binaries directory: $SOURCE_DIR"

Set-Location $PSScriptRoot

$wixCmd = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wixCmd) {
    Fail "WiX 5 CLI (wix) not found in PATH. Install with: dotnet tool install --global wix"
}

Write-Host "Adding required WiX extensions..."
wix extension add WixToolset.UI.wixext | Out-Null
wix extension add WixToolset.Util.wixext | Out-Null

$env:SRCDIR = $SOURCE_DIR

Write-Host "Harvesting application directory..."
if (Test-Path fragment.wxs) { Remove-Item fragment.wxs -Force }
wix harvest dir "$SOURCE_DIR" `
    -o fragment.wxs `
    -gg `
    -directory-ref INSTALLDIR `
    -component-group ApplicationFiles `
    -var env.SRCDIR `
    -scom -sreg -sfrag -srd

Write-Host "Building MSI..."
$OutputMsi = "ykman-$Arch.msi"
if (Test-Path $OutputMsi) { Remove-Item $OutputMsi -Force }

$Intermediate = Join-Path $PSScriptRoot "wix-int-$Arch"
if (Test-Path $Intermediate) { Remove-Item $Intermediate -Recurse -Force }
New-Item -ItemType Directory -Path $Intermediate | Out-Null

wix build `
    ykman.wxs fragment.wxs `
    -d ProductVersion=$SIMPLE_VERSION `
    -d PackagePlatform=$Arch `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -arch $Arch `
    --intermediate "$Intermediate" `
    -o $OutputMsi

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutputMsi)) {
    Fail "wix build failed or MSI not produced."
}

$FinalPath = Join-Path $CWD "ykman-$Arch.msi"
if (Test-Path $FinalPath) { Remove-Item $FinalPath -Force }
Move-Item $OutputMsi $FinalPath

Write-Host "MSI created: $FinalPath"

Remove-Item fragment.wxs -Force
if (Test-Path $Intermediate) { Remove-Item $Intermediate -Recurse -Force }

Set-Location $CWD
Write-Host "Done."