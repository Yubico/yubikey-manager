$ErrorActionPreference = 'Stop'
$archive = Join-Path $env:RUNNER_TEMP 'wix314-binaries.zip'
Invoke-WebRequest 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip' -OutFile $archive
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne '6AC824E1642D6F7277D0ED7EA09411A508F6116BA6FAE0AA5F2C7DAA2FF43D31') {
    throw 'WiX download checksum mismatch'
}
$wixDir = Join-Path $env:RUNNER_TEMP 'wix314'
Expand-Archive $archive -DestinationPath $wixDir
"WIX_BIN=$wixDir" >> $env:GITHUB_ENV
