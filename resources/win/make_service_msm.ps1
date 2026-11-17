param(
    [Parameter(Mandatory = $true)][string]$ServiceSource,
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64',
    [string]$OutputPath = (Join-Path (Get-Location) 'ykman-service.msm'),
    [string]$WixBin = "$env:WIX\bin"
)

$ErrorActionPreference = 'Stop'
$ServiceSource = (Resolve-Path $ServiceSource).Path
if (-not [IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path (Get-Location) $OutputPath
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$serviceVersion = & "$PSScriptRoot\get_msi_version.ps1" -Path $ServiceSource
$objectPath = [IO.Path]::ChangeExtension($OutputPath, '.wixobj')
try {
    & "$WixBin\candle.exe" "$PSScriptRoot\ykman-service.wxs" "-dServiceSource=$ServiceSource" "-dServiceVersion=$serviceVersion" "-dPlatform=$Architecture" -arch $Architecture -out $objectPath
    if ($LASTEXITCODE -ne 0) { throw 'Service module compilation failed' }
    # WiX 3's merge-module ICE39 predates the ARM64 summary-information platform.
    [string[]]$validation = if ($Architecture -eq 'arm64') { @('-sice:ICE39') } else { @() }
    & "$WixBin\light.exe" $objectPath -out $OutputPath @validation
    if ($LASTEXITCODE -ne 0) { throw 'Service module linking failed' }
} finally {
    if (Test-Path $objectPath) { Remove-Item $objectPath }
    $symbolsPath = [IO.Path]::ChangeExtension($OutputPath, '.wixpdb')
    if (Test-Path $symbolsPath) { Remove-Item $symbolsPath }
}
