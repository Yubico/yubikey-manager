Vagrant VM for building in Windows
===


Usage
---

The following steps assume using the VirtualBox provider.

 1. _Optional:_ Modify the USB passthrough settings in the `Vagrantfile` as
    necessary. The default rules will make the VM capture all YubiKey 4s with
    _all_ of the OTP, U2F and CCID transport modes enabled (device ID
    `1050:0407`).

 2. Fire up the VM and wait for provisioning to finish:

        $ cd yubikey-manager/vagrant/build-windows
        $ vagrant up

    This can take a few minutes. Also review the output from `vagrant up` to
    ensure the provisioner installs all dependencies successfully.

 3. Log in as user `vagrant` with password `vagrant`
 4. Open a command prompt with administrator privileges (keyboard shortcut:
    `<Win>` `c` `m` `d` `<Ctrl>+<Shift>+<Enter>`)
 5. Navigate to the `Z:` drive. If this fails, map the drive manually:

        C:\Users\vagrant> net use Z: \\VBOXSVR\vagrant

 6. Build the program

        Z:\> pip install -e .

    If this fails with "command not found" (this seems to happen if you log in
    before provisioning finishes), try running `refreshenv` to refresh the
    `PATH`. If it still fails, discard the VM and try again from (1).

 7. Run the program

        Z:\> ykman info
        Z:\> ykman slot info
        Z:\> ykman oath list
        Z:\> ykman openpgp touch sig on
        Z:\> ykman piv info
