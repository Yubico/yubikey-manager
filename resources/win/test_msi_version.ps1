$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory $root | Out-Null
try {
    $cases = @(
        @{ Numeric = '6.0.0.0'; Text = '6.0.0-alpha.0'; Expected = '6.0.0' },
        @{ Numeric = '6.0.1.0'; Text = '6.0.0-beta.0'; Expected = '6.0.1' },
        @{ Numeric = '6.0.2.0'; Text = '6.0.0-rc.0'; Expected = '6.0.2' },
        @{ Numeric = '6.0.2.0'; Text = '6.0.0'; Expected = '6.0.2' },
        @{ Numeric = '6.0.3.0'; Text = '6.0.1'; Expected = '6.0.3' },
        @{ Numeric = '1.0.0.0'; Text = '1.0.0-alpha.0'; Expected = '1.0.0' },
        @{ Numeric = '256.0.0.0'; Text = '6.0.0-alpha.0'; Expected = $null },
        @{ Numeric = '6.256.0.0'; Text = '6.0.0-alpha.0'; Expected = $null },
        @{ Numeric = '6.0.0.1'; Text = '6.0.0-alpha.0'; Expected = $null }
    )
    for ($i = 0; $i -lt $cases.Count; $i++) {
        $case = $cases[$i]
        $path = Join-Path $root "version$i.dll"
        $source = @"
using System.Reflection;
[assembly: AssemblyFileVersion("$($case.Numeric)")]
[assembly: AssemblyInformationalVersion("$($case.Text)")]
public class VersionFixture$i {}
"@
        $sourcePath = Join-Path $root "version$i.cs"
        Set-Content $sourcePath $source
        & "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:library "/out:$path" $sourcePath
        if ($LASTEXITCODE -ne 0) { throw "Version fixture compilation failed: $($case.Numeric)" }
        $fixture = [Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        $numeric = "$($fixture.FileMajorPart).$($fixture.FileMinorPart).$($fixture.FileBuildPart).$($fixture.FilePrivatePart)"
        if ($numeric -ne $case.Numeric -or $fixture.ProductVersion -ne $case.Text) {
            throw "Version fixture resources do not match $($case.Numeric) / $($case.Text)"
        }
        $failure = $null
        try {
            $actual = & "$PSScriptRoot\get_msi_version.ps1" -Path $path
        } catch {
            $failure = $_
        }
        if ($null -eq $case.Expected) {
            if ($null -eq $failure -or $failure.Exception.Message -notlike '*within MSI*') {
                throw "Version $($case.Numeric) must be rejected by MSI version validation"
            }
        } else {
            if ($null -ne $failure) { throw $failure }
            if ($actual -ne $case.Expected) {
                throw "Expected $($case.Expected), got $actual for $($case.Numeric)"
            }
        }
    }
    Write-Host 'MSI version extraction preserves numeric ordering and rejects unsupported versions.'
} finally {
    Remove-Item -Recurse $root
}
