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

## License

Apache-2.0
