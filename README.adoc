== YubiKey Manager CLI
image:https://github.com/Yubico/yubikey-manager/workflows/build/badge.svg["Build Status", link="https://github.com/Yubico/yubikey-manager/actions"]

Python 3.7 (or later) library and command line tool for configuring a YubiKey.
If you're looking for the graphical application, it's https://developers.yubico.com/yubikey-manager-qt/[here].

=== Usage
For more usage information and examples, see the https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html[YubiKey Manager CLI User Manual].

....
Usage: ykman [OPTIONS] COMMAND [ARGS]...

  Configure your YubiKey via the command line.

  Examples:

    List connected YubiKeys, only output serial number:
    $ ykman list --serials

    Show information about YubiKey with serial number 0123456:
    $ ykman --device 0123456 info

Options:
  -v, --version                   Show version information about the app
  -d, --device SERIAL             Specify which YubiKey to interact with by serial number.
  -l, --log-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]
                                  Enable logging at given verbosity level.
  --log-file FILE                 Write logs to the given FILE instead of standard error; ignored
                                  unless --log-level is also set.

  -r, --reader NAME               Use an external smart card reader. Conflicts with --device and list.
  --diagnose                      Show diagnostics information useful for troubleshooting.
  -h, --help                      Show this message and exit.

Commands:
  info     Show general information.
  list     List connected YubiKeys.
  config   Enable/Disable applications.
  fido     Manage the FIDO applications.
  oath     Manage the OATH Application.
  openpgp  Manage the OpenPGP Application.
  otp      Manage the OTP Application.
  piv      Manage the PIV Application.
....

The `--help` argument can also be used to get detailed information about specific
subcommands:

    ykman oath --help

=== Installation
YubiKey Manager can be installed independently of platform by using pip (or
equivalent):

  pip install --user yubikey-manager

On Linux platforms you will need `pcscd` installed and running to be able to
communicate with a YubiKey over the SmartCard interface. Additionally, you may
need to set permissions for your user to access YubiKeys via the HID interfaces.
More information available link:doc/Device_Permissions.adoc[here].

Some of the libraries used by yubikey-manager have C-extensions, and may require
additional dependencies to build, such as http://www.swig.org/[swig] and
potentially https://pcsclite.alioth.debian.org/pcsclite.html[PCSC lite].

=== Pre-build packages
Pre-built packages specific to your platform may be available from Yubico or
third parties. Please refer to your platforms native package manager for
detailed instructions on how to install, if available.

==== Windows
The command line tool ykman.exe is provided as part of the installer for the
https://developers.yubico.com/yubikey-manager-qt/[YubiKey Manager] on Windows.

==== MacOS
Packages for MacOS are available from Homebrew and MacPorts.

===== Input Monitoring access on MacOS
When running one of the `ykman otp` commands you may run into an error such as:
`Failed to open device for communication: -536870174`. This indicates a problem
with the permission to access the OTP (keyboard) USB interface.
  
To access a YubiKey over this interface the application needs the `Input
Monitoring` permission. If you are not automatically prompted to grant this
permission, you may have to do so manually. Note that it is the _terminal_ you
are using that needs the permission, not the ykman executable.

To add your terminal application to the `Input Monitoring` permission list, go
to `System Preferences -> Security & Privacy -> Privacy -> Input Monitoring` to
resolve this.

==== Linux
Packages are available for several Linux distributions by third party package
maintainers.
Yubico also provides packages for Ubuntu in the yubico/stable PPA (for amd64
ONLY, other architectures such as arm should use the general `pip` instructions
above instead):

  $ sudo apt-add-repository ppa:yubico/stable
  $ sudo apt update
  $ sudo apt install yubikey-manager

==== FreeBSD
Althought not being officially supported on this platform, YubiKey Manager can be
installed on FreeBSD. It's available via its ports tree or as pre-built package.
Should you opt to install and use YubiKey Manager on this platform, please be aware
that it's **NOT** maintained by Yubico.

To install the binary package, use `pkg install pyXY-yubikey-manager`, with `pyXY`
specifying the version of Python the package was built for, so in order to install
YubiKey Manager for Python 3.8, use:

  # pkg install py38-yubikey-manager

For more information about how to install packages or ports on FreeBSD, please refer
to its official documentation: https://docs.freebsd.org/en/books/handbook/ports[FreeBSD Handbook].

In order to use `ykman otp` commands, you need to make sure the _uhid(4)_ driver
attaches to the USB device:

  # usbconfig ugenX.Y add_quirk UQ_KBD_IGNORE
  # usbconfig ugenX.Y reset

The correct device to operate on _(ugenX.Y)_ can be determined using
`usbconfig list`.

When using FreeBSD 13 or higher, you can switch to the more modern _hidraw(4)_
driver. This allows YubiKey Manager to access OTP HID in a non-exclusive way,
so that the key will still function as a USB keyboard:

  # sysrc kld_list+="hidraw hkbd"
  # cat >>/boot/loader.conf<<EOF
  hw.usb.usbhid.enable="1"
  hw.usb.quirk.0="0x1050 0x0010 0 0xffff UQ_KBD_IGNORE"  # YKS_OTP
  hw.usb.quirk.1="0x1050 0x0110 0 0xffff UQ_KBD_IGNORE"  # NEO_OTP
  hw.usb.quirk.2="0x1050 0x0111 0 0xffff UQ_KBD_IGNORE"  # NEO_OTP_CCID
  hw.usb.quirk.3="0x1050 0x0114 0 0xffff UQ_KBD_IGNORE"  # NEO_OTP_FIDO
  hw.usb.quirk.4="0x1050 0x0116 0 0xffff UQ_KBD_IGNORE"  # NEO_OTP_FIDO_CCID
  hw.usb.quirk.5="0x1050 0x0401 0 0xffff UQ_KBD_IGNORE"  # YK4_OTP
  hw.usb.quirk.6="0x1050 0x0403 0 0xffff UQ_KBD_IGNORE"  # YK4_OTP_FIDO
  hw.usb.quirk.7="0x1050 0x0405 0 0xffff UQ_KBD_IGNORE"  # YK4_OTP_CCID
  hw.usb.quirk.8="0x1050 0x0407 0 0xffff UQ_KBD_IGNORE"  # YK4_OTP_FIDO_CCID
  hw.usb.quirk.9="0x1050 0x0410 0 0xffff UQ_KBD_IGNORE"  # YKP_OTP_FIDO
  EOF
  # reboot

==== Source
To install from source, see the link:doc/Development.adoc[development]
instructions.

=== Shell completion

Experimental shell completion for the command line tool is available, provided
by the underlying CLI library (`click`) but it is not enabled by default. To
enable it, run this command once (for Bash):

  $ source <(_YKMAN_COMPLETE=bash_source ykman | sudo tee /etc/bash_completion.d/ykman)

More information on shell completion (including instructions for zch) is
available here:
https://click.palletsprojects.com/en/8.0.x/shell-completion
