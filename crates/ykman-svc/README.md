# ykman-svc

Background service for YubiKey Manager, providing a persistent process that
maintains device state and serves requests from client applications via a
JSON-RPC interface over named pipes (Windows) or Unix domain sockets.

## Purpose

This service allows Yubico client applications such as the ykman CLI to access
the FIDO functionality of a YubiKey on Windows without requiring running them
as administrator.

## Usage

The service is typically started automatically by system service manager rather
than invoked directly. It is bundled with the Windows installers for relevant
applications.

## Windows packaging

MSI applications include the merge module built by
`resources/win/make_service_msm.ps1`. The canonical module source lives in this
repository; consumers must not create their own service components. It installs
`ykman-svc.exe` in `%ProgramFiles%\Yubico\YubiKey Manager Service`, independently
of either application's install directory. Windows Installer tracks all
products using the component, so removing one product leaves the service
running and removing the last product removes it.

Keep the module's package and component GUIDs stable for each architecture.
Consumers must use the same architecture; the product installers reject a
conflicting installed service architecture. The service's Cargo package version
provides its Windows file version: increment it whenever shipping a new service
binary, and retain RPC compatibility with supported clients. File versioning
prevents a normal installation of an older app from downgrading the service.

Yubico Authenticator's MSIX package instead runs
`ykman-svc.exe run --authenticator-msix`. This uses service name
`yubico-authenticator-svc` and pipe `\\.\pipe\yubico-authenticator-svc`.
Clients with the `YubicoAB.YubicoAuthenticator` Windows package identity select
that pipe automatically, including the helper child process. Unpackaged clients
continue to use `\\.\pipe\ykman-svc`; there is no fallback between the two.
Signature verification and SCM image lookup use the corresponding service.

Run `resources/win/test_service_msm.ps1` elevated to test shared component
ownership, both install/uninstall orders, upgrades, and repair with an isolated test
service. It does not modify an installed `ykman-svc`.

## Platform support

This service is only intended to be run on Windows. Other platform support
exists for development and testing purposes only.

| Platform | IPC mechanism |
|----------|---------------|
| Windows | Named pipes + Windows Service |
| Linux/macOS | Unix domain sockets |

## Security model

The service exposes raw YubiKey transports (APDU, CTAP HID, and OTP HID) to
authorized local clients. On Windows, the named pipe is accessible to
authenticated users so non-elevated clients can connect, but both peers verify
that the other process is signed with the same Authenticode certificate. Unsigned
debug builds skip peer verification for development only and should not be used
as a production service.

The service limits concurrent clients and validates raw transport request sizes,
but callers should still treat access to the service as equivalent to direct
access to the connected YubiKey interfaces.

Clients can enumerate attached YubiKeys and read cached device information
without claiming them. The first connection or device reinsert request claims
the YubiKey exclusively for that client session; other clients can still list
it but cannot open a connection until the client's last connection is closed
or the session ends. FIDO touch selection reserves candidate devices while it
runs.

## License

Apache-2.0
