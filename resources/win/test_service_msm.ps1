# Run elevated on a Windows build host. Uses an isolated test service, not ykman-svc.
param(
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64',
    [string]$WixBin = "$env:WIX\bin"
)
$ErrorActionPreference = 'Stop'
$testName = 'Yubico-MergeModule-Test'
if (Get-Service $testName -ErrorAction SilentlyContinue) {
    throw "Test service $testName already exists"
}
$root = Join-Path $env:TEMP ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory $root | Out-Null
$products = @(0..3 | ForEach-Object { [Guid]::NewGuid().ToString('B') })
$upgradeCodes = @([Guid]::NewGuid().ToString('B'), [Guid]::NewGuid().ToString('B'))
$succeeded = $false
$installedProducts = [Collections.Generic.HashSet[string]]::new()

function Run-Msi([string[]]$Arguments) {
    $process = Start-Process msiexec.exe -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "msiexec failed ($($process.ExitCode)): $Arguments; see $root"
    }
}
function Assert-Running {
    $service = Get-Service $testName
    if ($service.Status -ne 'Running') { throw "Shared service is not running: $($service.Status)" }
}

try {
    $source = @"
using System.Reflection;
using System.ServiceProcess;
[assembly: AssemblyFileVersion("1.0.0.0")]
public class TestService : ServiceBase {
    public TestService() { ServiceName = "$testName"; }
    public static void Main() { Run(new TestService()); }
}
"@
    Set-Content "$root\service.cs" $source
    & "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe "/out:$root\service.exe" /reference:System.ServiceProcess.dll "$root\service.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Test service compilation failed' }
    $module = Get-Content "$PSScriptRoot\ykman-service.wxs" -Raw
    $module = $module.Replace('ykman-svc', $testName).Replace('YubiKey Manager Service', $testName)
    foreach ($guid in @('c871dc98-5a40-4875-8f79-45a493f89826', '2f14e8ed-0490-4c66-b6ab-9d90f855b1c4', '085d53ef-8e28-5d07-82c8-fcf8a7ce74bd', 'b4e8d2f3-6a9b-4c0f-ad2e-3f5a7b9c1d4e')) {
        $module = $module.Replace($guid, [Guid]::NewGuid().ToString())
    }
    Set-Content "$root\ykman-service.wxs" $module
    Copy-Item "$PSScriptRoot\make_service_msm.ps1" $root
    & "$root\make_service_msm.ps1" -ServiceSource "$root\service.exe" -Architecture $Architecture -OutputPath "$root\service.msm" -WixBin $WixBin
    $installerVersion = if ($Architecture -eq 'arm64') { '500' } else { '301' }
    for ($i = 0; $i -lt 4; $i++) {
        $owner = $i % 2
        $version = if ($i -lt 2) { '1.0.0' } else { '2.0.0' }
        $product = @"
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
 <Product Id="$($products[$i])" Name="Merge module test $owner" Language="1033" Version="$version" Manufacturer="Yubico" UpgradeCode="$($upgradeCodes[$owner])">
  <Package InstallerVersion="$installerVersion" InstallScope="perMachine" Compressed="yes" />
  <MajorUpgrade Schedule="afterInstallValidate" DowngradeErrorMessage="A newer version is installed." />
  <Media Id="1" Cabinet="test.cab" EmbedCab="yes" />
  <Directory Id="TARGETDIR" Name="SourceDir"><Merge Id="Service" SourceFile="$root\service.msm" Language="1033" DiskId="1" /></Directory>
  <Feature Id="ServiceFeature" Level="1"><MergeRef Id="Service" /></Feature>
 </Product>
</Wix>
"@
        Set-Content "$root\product$i.wxs" $product
        & "$WixBin\candle.exe" "$root\product$i.wxs" -arch $Architecture -out "$root\product$i.wixobj"
        if ($LASTEXITCODE -ne 0) { throw 'Test MSI compilation failed' }
        & "$WixBin\light.exe" "$root\product$i.wixobj" -out "$root\product$i.msi"
        if ($LASTEXITCODE -ne 0) { throw 'Test MSI linking failed' }
    }
    foreach ($first in @(0, 1)) {
        $last = 1 - $first
        Run-Msi -Arguments @('/i', "`"$root\product$first.msi`"", '/qn', '/norestart', '/l*v', "`"$root\install$first.log`"")
        [void]$installedProducts.Add($products[$first])
        Run-Msi -Arguments @('/i', "`"$root\product$last.msi`"", '/qn', '/norestart', '/l*v', "`"$root\install$last.log`"")
        [void]$installedProducts.Add($products[$last])
        Assert-Running
        $upgrade = $first + 2
        Run-Msi -Arguments @('/i', "`"$root\product$upgrade.msi`"", '/qn', '/norestart', '/l*v', "`"$root\upgrade$first.log`"")
        [void]$installedProducts.Remove($products[$first])
        [void]$installedProducts.Add($products[$upgrade])
        Assert-Running
        Run-Msi -Arguments @('/x', $products[$upgrade], '/qn', '/norestart', '/l*v', "`"$root\uninstall$first.log`"")
        [void]$installedProducts.Remove($products[$upgrade])
        Assert-Running
        Run-Msi -Arguments @('/fa', $products[$last], '/qn', '/norestart', '/l*v', "`"$root\repair$last.log`"")
        Assert-Running
        $upgrade = $last + 2
        Run-Msi -Arguments @('/i', "`"$root\product$upgrade.msi`"", '/qn', '/norestart', '/l*v', "`"$root\upgrade$last.log`"")
        [void]$installedProducts.Remove($products[$last])
        [void]$installedProducts.Add($products[$upgrade])
        Assert-Running
        Run-Msi -Arguments @('/x', $products[$upgrade], '/qn', '/norestart', '/l*v', "`"$root\uninstall$last.log`"")
        [void]$installedProducts.Remove($products[$upgrade])
        if (Get-Service $testName -ErrorAction SilentlyContinue) { throw 'Last uninstall left the test service behind' }
        if (Test-Path (Join-Path $env:ProgramFiles "Yubico\$testName\$testName.exe")) { throw 'Last uninstall left the test executable behind' }
    }
    Write-Host 'Both install/uninstall orders, upgrades and repair preserve shared service ownership.'
    $succeeded = $true
} finally {
    foreach ($product in $installedProducts) {
        $process = Start-Process msiexec.exe -ArgumentList @('/x', $product, '/qn', '/norestart') -Wait -PassThru
        if ($process.ExitCode -notin 0, 1605, 3010) { Write-Warning "Test product cleanup failed: $($process.ExitCode)" }
    }
    # Preserve logs on failure; remove only this test's resolved temporary directory on success.
    if ($succeeded) { Remove-Item -Recurse $root }
    else { Write-Host "Test artifacts: $root" }
}
