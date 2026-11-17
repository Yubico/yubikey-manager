param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = 'Stop'
$file = (Resolve-Path $Path).Path
$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($file)
if (-not $version.FileVersion) {
    throw "$file must have a Windows file version"
}
if ($version.FileMajorPart -gt 255 -or $version.FileMinorPart -gt 255 -or $version.FilePrivatePart -ne 0) {
    throw "$file must have a numeric version within MSI major.minor.build limits and a zero fourth component"
}
"$($version.FileMajorPart).$($version.FileMinorPart).$($version.FileBuildPart)"
