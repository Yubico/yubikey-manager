param(
  [string]$Arch = "x64"  # x64 or arm64
)

# WiX 5 build script for ykman.msi

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
$SIMPLE_VERSION = "$(($baseVersion.Split('-')[0])).0"  # Force 4th field for MSI

Write-Host "Raw version: $baseVersion"
Write-Host "MSI ProductVersion: $SIMPLE_VERSION"
Write-Host "Architecture: $Arch"
Write-Host "Binaries directory: $SOURCE_DIR"

Set-Location $PSScriptRoot

# Ensure WiX CLI available
$wixCmd = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wixCmd) {
  Fail "WiX CLI (wix) not found. Install with: dotnet tool install --global wix"
}

Write-Host "Adding required WiX extensions..."
wix extension add WixToolset.UI.wixext | Out-Null
wix extension add WixToolset.Util.wixext | Out-Null

# ENV variable still used in File Source attributes if desired
$env:SRCDIR = $SOURCE_DIR

Write-Host "Generating fragment.wxs (manual harvest)..."

# Collect files (recursive)
$allFiles = Get-ChildItem -Path $SOURCE_DIR -Recurse -File | Where-Object {
  $_.FullName -notmatch '\\__pycache__\\' -and
  $_.Extension -notin '.pdb', '.pyc', '.log'
}

if (-not $allFiles) {
  Fail "No files found to package in $SOURCE_DIR."
}

# Create relative paths
$relFiles = $allFiles | ForEach-Object {
  $_.FullName.Substring($SOURCE_DIR.Length + 1)
}

# Deterministic GUID based on combined relative file list (simple hash -> GUID)
$hashInput = ($relFiles | Sort-Object) -join '|'
# Deterministic GUID from an input string using SHA256 (truncate to 16 bytes)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($HashInput)
$sha   = [System.Security.Cryptography.SHA256]::Create()
$hash  = $sha.ComputeHash($bytes)              # 32 bytes

# Take the first 16 bytes for the GUID
$guidBytes = New-Object byte[] 16
[Array]::Copy($hash, 0, $guidBytes, 0, 16)

# Normalize to a valid RFC 4122 variant & set a version (use 4 here: "random" style, though deterministic)
$guidBytes[6] = ($guidBytes[6] -band 0x0F) -bor 0x40  # version 4
$guidBytes[8] = ($guidBytes[8] -band 0x3F) -bor 0x80  # variant bits 10xxxxxx

$componentGuid = ([Guid]::new($guidBytes)).ToString()

$fragmentContent = @()
$fragmentContent += '<?xml version="1.0" encoding="UTF-8"?>'
$fragmentContent += '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">'
$fragmentContent += '  <Fragment>'
$fragmentContent += '    <DirectoryRef Id="INSTALLDIR">'
$fragmentContent += "      <Component Id='AppFiles' Guid='$componentGuid'>"

# Make the first file the KeyPath
$first = $true
foreach ($rel in $relFiles) {
  $escaped = $rel -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'","&apos;"
  $sourceAttr = "$SOURCE_DIR\$escaped"
  if ($first) {
    $fragmentContent += "        <File Source='$sourceAttr' KeyPath='yes' />"
    $first = $false
  } else {
    $fragmentContent += "        <File Source='$sourceAttr' />"
  }
}

$fragmentContent += '      </Component>'
$fragmentContent += '    </DirectoryRef>'
$fragmentContent += '    <ComponentGroup Id="ApplicationFiles">'
$fragmentContent += '      <ComponentRef Id="AppFiles" />'
$fragmentContent += '    </ComponentGroup>'
$fragmentContent += '  </Fragment>'
$fragmentContent += '</Wix>'

Set-Content -Path fragment.wxs -Value ($fragmentContent -join "`n") -Encoding UTF8

Write-Host "fragment.wxs generated with $($relFiles.Count) files."

# Build MSI
$OutputMsi = "ykman-$Arch.msi"
if (Test-Path $OutputMsi) { Remove-Item $OutputMsi -Force }

Write-Host "Running wix build..."
wix build `
  ykman.wxs fragment.wxs `
  -d ProductVersion=$SIMPLE_VERSION `
  -ext WixToolset.UI.wixext `
  -ext WixToolset.Util.wixext `
  -arch $Arch `
  -o $OutputMsi

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutputMsi)) {
  Fail "wix build failed or MSI not produced."
}

$FinalPath = Join-Path $CWD "ykman-$Arch.msi"
if (Test-Path $FinalPath) { Remove-Item $FinalPath -Force }
Move-Item $OutputMsi $FinalPath

Write-Host "MSI created: $FinalPath"

Remove-Item fragment.wxs -Force

Set-Location $CWD
Write-Host "Done."
