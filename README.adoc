== YubiKey Manager CLI
image:https://github.com/Yubico/yubikey-manager/workflows/build/badge.svg["Build Status", link="https://github.com/Yubico/yubikey-manager/actions"]

Python library and command line tool for configuring a YubiKey. If you're looking for the full graphical application, which also includes the command line tool, it's https://developers.yubico.com/yubikey-manager-qt/[here].

=== Usage
For more usage information and examples, see the https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide[YubiKey Manager CLI User Manual].

....
Usage: ykman [OPTIONS] COMMAND [ARGS]...

  Configure your YubiKey via the command line.

  Examples:

    List connected YubiKeys, only output serial number:
    $ ykman list --serials

    Show information about YubiKey with serial number 0123456:
    $ ykman --device 0123456 info

Options:
  -v, --version
  -d, --device SERIAL
  -l, --log-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]
                                  Enable logging at given verbosity level.
  --log-file FILE                 Write logs to the given FILE instead of standard error; ignored unless --log-level is also set.
  -r, --reader NAME               Use an external smart card reader. Conflicts with --device and list.
  -h, --help                      Show this message and exit.

Commands:
  config   Enable/Disable applications.
  fido     Manage FIDO applications.
  info     Show general information.
  list     List connected YubiKeys.
  mode     Manage connection modes (USB Interfaces).
  oath     Manage OATH Application.
  openpgp  Manage OpenPGP Application.
  otp      Manage OTP Application.
  piv      Manage PIV Application.
....

=== Installation

==== Ubuntu

    $ sudo apt-add-repository ppa:yubico/stable
    $ sudo apt update
    $ sudo apt install yubikey-manager

==== macOS

    $ brew install ykman

==== Windows

The command line tool is installed together with the GUI version of https://developers.yubico.com/yubikey-manager-qt/[YubiKey Manager].

==== Pip

    $ pip install yubikey-manager

In order for the pip package to work, https://developers.yubico.com/yubikey-personalization/[ykpers] and http://libusb.info/[libusb] need to be installed on your system as well.
https://pyscard.sourceforge.io/[Pyscard] is also needed in some form, and if it's not installed pip builds it using http://www.swig.org/[swig] and potentially https://pcsclite.alioth.debian.org/pcsclite.html[PCSC lite].

==== Source
To install from source, see the link:doc/development.adoc[development] instructions.

=== Bash completion

Experimental Bash completion for the command line tool is available, but not 
enabled by default. To enable it, run this command once:

    $ source <(_YKMAN_COMPLETE=source ykman | sudo tee /etc/bash_completion.d/ykman)
