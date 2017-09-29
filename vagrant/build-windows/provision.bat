net use Z: \\VBOXSVR\vagrant

REM Install Chocolatey
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

choco install python2 -y
choco install swig -y --checksum 140f92dce638ca9ffbe442c2bc3d48c811c9a1cd0347896c757745afcce07f64 --checksumtype sha256
choco install vcpython27 -y

choco install 7zip -y

REM Download libusb DLL
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://github.com/libusb/libusb/releases/download/v1.0.21/libusb-1.0.21.7z', 'libusb-1.0.21.7z')"
7z e libusb-1.0.21.7z MS64\dll\libusb-1.0.dll

REM Download ykpers DLLs
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://developers.yubico.com/yubikey-personalization/Releases/ykpers-1.18.0-win64.zip', 'ykpers-1.18.0-win64.zip')"
7z e ykpers-1.18.0-win64.zip bin/libykpers-1-1.dll bin/libyubikey-0.dll bin/libjson-c-2.dll

REM Download libu2f-host DLLs
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://developers.yubico.com/libu2f-host/Releases/libu2f-host-1.1.4-win64.zip', 'libu2f-host-1.1.4-win64.zip')"
7z e libu2f-host-1.1.4-win64.zip bin/libu2f-host-0.dll bin/libhidapi-0.dll

REM Move DLLs to installation directory
mv libusb-1.0.dll libykpers-1-1.dll libyubikey-0.dll libjson-c-2.dll libu2f-host-0.dll libhidapi-0.dll Z:\
