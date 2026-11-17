param(
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path $BuildDir).Path
$msi = if ($Architecture -eq 'arm64') { 'ykman-arm64.msi' } else { 'ykman.msi' }
$cliVersion = & "$PSScriptRoot\get_msi_version.ps1" -Path "$root\ykman\ykman.exe"
$serviceVersion = & "$PSScriptRoot\get_msi_version.ps1" -Path "$root\ykman\ykman-svc.exe"
$installer = New-Object -ComObject WindowsInstaller.Installer
foreach ($expected in @(
    @{ Path = $msi; Query = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"; Version = $cliVersion },
    @{ Path = 'ykman-service.msm'; Query = 'SELECT Version FROM ModuleSignature'; Version = $serviceVersion }
)) {
    $database = $installer.OpenDatabase((Resolve-Path "$root\$($expected.Path)").Path, 0)
    $view = $database.OpenView($expected.Query)
    $view.Execute()
    $record = $view.Fetch()
    if ($null -eq $record) {
        throw "$($expected.Path) must have version $($expected.Version)"
    }
    $actual = [version]$record.StringData(1)
    if ($actual.ToString(3) -ne $expected.Version -or $actual.Revision -gt 0) {
        throw "$($expected.Path) must have version $($expected.Version), got $actual"
    }
    $view.Close()
}
