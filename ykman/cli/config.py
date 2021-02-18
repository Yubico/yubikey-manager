# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from yubikit.core import TRANSPORT
from yubikit.management import (
    ManagementSession,
    DeviceConfig,
    CAPABILITY,
    USB_INTERFACE,
    DEVICE_FLAG,
    Mode,
)
from .. import YUBIKEY
from .util import (
    click_postpone_execution,
    click_force_option,
    click_prompt,
    EnumChoice,
    cli_fail,
)
import os
import re
import click
import logging


logger = logging.getLogger(__name__)


CLEAR_LOCK_CODE = "0" * 32


def prompt_lock_code(prompt="Enter your lock code"):
    return click_prompt(prompt, default="", hide_input=True, show_default=False)


@click.group()
@click.pass_context
@click_postpone_execution
def config(ctx):
    """
    Enable or disable applications.

    The applications may be enabled and disabled independently
    over different transports (USB and NFC). The configuration may
    also be protected by a lock code.

    Examples:

    \b
      Disable PIV over NFC:
      $ ykman config nfc --disable PIV

    \b
      Enable all applications over USB:
      $ ykman config usb --enable-all

    \b
      Generate and set a random application lock code:
      $ ykman config set-lock-code --generate
    """
    ctx.obj["controller"] = ManagementSession(ctx.obj["conn"])


def _require_config(ctx):
    info = ctx.obj["info"]
    if info.version < (5, 0, 0):
        cli_fail(
            "Configuring applications is not supported on this YubiKey. "
            "Use the `mode` command to configure USB interfaces."
        )


@config.command("set-lock-code")
@click.pass_context
@click_force_option
@click.option("-l", "--lock-code", metavar="HEX", help="Current lock code.")
@click.option(
    "-n",
    "--new-lock-code",
    metavar="HEX",
    help="New lock code. Conflicts with --generate.",
)
@click.option("-c", "--clear", is_flag=True, help="Clear the lock code.")
@click.option(
    "-g",
    "--generate",
    is_flag=True,
    help="Generate a random lock code. Conflicts with --new-lock-code.",
)
def set_lock_code(ctx, lock_code, new_lock_code, clear, generate, force):
    """
    Set or change the configuration lock code.

    A lock code may be used to protect the application configuration.
    The lock code must be a 32 characters (16 bytes) hex value.
    """

    _require_config(ctx)
    info = ctx.obj["info"]
    app = ctx.obj["controller"]

    def prompt_new_lock_code():
        return prompt_lock_code(prompt="Enter your new lock code")

    def prompt_current_lock_code():
        return prompt_lock_code(prompt="Enter your current lock code")

    def change_lock_code(lock_code, new_lock_code):
        lock_code = _parse_lock_code(ctx, lock_code)
        new_lock_code = _parse_lock_code(ctx, new_lock_code)
        try:
            app.write_device_config(
                None, False, lock_code, new_lock_code,
            )
        except Exception as e:
            logger.error("Changing the lock code failed", exc_info=e)
            cli_fail("Failed to change the lock code. Wrong current code?")

    def set_lock_code(new_lock_code):
        new_lock_code = _parse_lock_code(ctx, new_lock_code)
        try:
            app.write_device_config(
                None, False, None, new_lock_code,
            )
        except Exception as e:
            logger.error("Setting the lock code failed", exc_info=e)
            cli_fail("Failed to set the lock code.")

    if generate and new_lock_code:
        ctx.fail("Invalid options: --new-lock-code conflicts with --generate.")

    if clear:
        new_lock_code = CLEAR_LOCK_CODE

    if generate:
        new_lock_code = os.urandom(16).hex()
        click.echo(f"Using a randomly generated lock code: {new_lock_code}")
        force or click.confirm(
            "Lock configuration with this lock code?", abort=True, err=True
        )

    if info.is_locked:
        if lock_code:
            if new_lock_code:
                change_lock_code(lock_code, new_lock_code)
            else:
                new_lock_code = prompt_new_lock_code()
                change_lock_code(lock_code, new_lock_code)
        else:
            if new_lock_code:
                lock_code = prompt_current_lock_code()
                change_lock_code(lock_code, new_lock_code)
            else:
                lock_code = prompt_current_lock_code()
                new_lock_code = prompt_new_lock_code()
                change_lock_code(lock_code, new_lock_code)
    else:
        if lock_code:
            cli_fail(
                "There is no current lock code set. Use --new-lock-code to set one."
            )
        else:
            if new_lock_code:
                set_lock_code(new_lock_code)
            else:
                new_lock_code = prompt_new_lock_code()
                set_lock_code(new_lock_code)


@config.command()
@click.pass_context
@click_force_option
@click.option(
    "-e",
    "--enable",
    multiple=True,
    type=EnumChoice(CAPABILITY, hidden=[CAPABILITY.HSMAUTH]),
    help="Enable applications.",
)
@click.option(
    "-d",
    "--disable",
    multiple=True,
    type=EnumChoice(CAPABILITY, hidden=[CAPABILITY.HSMAUTH]),
    help="Disable applications.",
)
@click.option(
    "-l", "--list", "list_enabled", is_flag=True, help="List enabled applications."
)
@click.option("-a", "--enable-all", is_flag=True, help="Enable all applications.")
@click.option(
    "-L",
    "--lock-code",
    metavar="HEX",
    help="Current application configuration lock code.",
)
@click.option(
    "--touch-eject",
    is_flag=True,
    help="When set, the button toggles the state"
    " of the smartcard between ejected and inserted. (CCID only).",
)
@click.option("--no-touch-eject", is_flag=True, help="Disable touch eject (CCID only).")
@click.option(
    "--autoeject-timeout",
    required=False,
    type=int,
    default=None,
    metavar="SECONDS",
    help="When set, the smartcard will automatically eject"
    " after the given time. Implies --touch-eject.",
)
@click.option(
    "--chalresp-timeout",
    required=False,
    type=int,
    default=None,
    metavar="SECONDS",
    help="Sets the timeout when waiting for touch"
    " for challenge-response in the OTP application.",
)
def usb(
    ctx,
    enable,
    disable,
    list_enabled,
    enable_all,
    touch_eject,
    no_touch_eject,
    autoeject_timeout,
    chalresp_timeout,
    lock_code,
    force,
):
    """
    Enable or disable applications over USB.
    """
    _require_config(ctx)

    def ensure_not_all_disabled(ctx, usb_enabled):
        for app in CAPABILITY:
            if app & usb_enabled:
                return
        ctx.fail("Can not disable all applications over USB.")

    if not (
        list_enabled
        or enable_all
        or enable
        or disable
        or touch_eject
        or no_touch_eject
        or autoeject_timeout
        or chalresp_timeout
    ):
        ctx.fail("No configuration options chosen.")

    info = ctx.obj["info"]
    usb_supported = info.supported_capabilities[TRANSPORT.USB]
    usb_enabled = info.config.enabled_capabilities[TRANSPORT.USB]
    flags = info.config.device_flags

    if enable_all:
        enable = [c for c in CAPABILITY if c in usb_supported]

    _ensure_not_invalid_options(ctx, enable, disable)

    if touch_eject and no_touch_eject:
        ctx.fail("Invalid options.")

    if not usb_supported:
        cli_fail("USB not supported on this YubiKey.")

    if list_enabled:
        _list_apps(ctx, usb_enabled)

    if touch_eject:
        flags |= DEVICE_FLAG.EJECT
    if no_touch_eject:
        flags &= ~DEVICE_FLAG.EJECT

    for app in enable:
        if app & usb_supported:
            usb_enabled |= app
        else:
            cli_fail(f"{app.name} not supported over USB on this YubiKey.")
    for app in disable:
        if app & usb_supported:
            usb_enabled &= ~app
        else:
            cli_fail(f"{app.name} not supported over USB on this YubiKey.")

    ensure_not_all_disabled(ctx, usb_enabled)

    f_confirm = ""
    if enable:
        f_confirm += f"Enable {', '.join(str(app) for app in enable)}.\n"
    if disable:
        f_confirm += f"Disable {', '.join(str(app) for app in disable)}.\n"
    if touch_eject:
        f_confirm += "Set touch eject.\n"
    elif no_touch_eject:
        f_confirm += "Disable touch eject.\n"
    if autoeject_timeout:
        f_confirm += f"Set autoeject timeout to {autoeject_timeout}.\n"
    if chalresp_timeout:
        f_confirm += f"Set challenge-response timeout to {chalresp_timeout}.\n"
    f_confirm += "Configure USB?"

    is_locked = info.is_locked

    if force and is_locked and not lock_code:
        cli_fail("Configuration is locked - please supply the --lock-code option.")
    if lock_code and not is_locked:
        cli_fail("Configuration is not locked - please remove the --lock-code option.")

    force or click.confirm(f_confirm, abort=True, err=True)

    if is_locked and not lock_code:
        lock_code = prompt_lock_code()

    if lock_code:
        lock_code = _parse_lock_code(ctx, lock_code)

    app = ctx.obj["controller"]
    try:
        app.write_device_config(
            DeviceConfig(
                {TRANSPORT.USB: usb_enabled},
                autoeject_timeout,
                chalresp_timeout,
                flags,
            ),
            True,
            lock_code,
        )
    except Exception as e:
        logger.error("Failed to write config", exc_info=e)
        cli_fail("Failed to configure USB applications.")


@config.command()
@click.pass_context
@click_force_option
@click.option(
    "-e",
    "--enable",
    multiple=True,
    type=EnumChoice(CAPABILITY, hidden=[CAPABILITY.HSMAUTH]),
    help="Enable applications.",
)
@click.option(
    "-d",
    "--disable",
    multiple=True,
    type=EnumChoice(CAPABILITY, hidden=[CAPABILITY.HSMAUTH]),
    help="Disable applications.",
)
@click.option("-a", "--enable-all", is_flag=True, help="Enable all applications.")
@click.option("-D", "--disable-all", is_flag=True, help="Disable all applications")
@click.option(
    "-l", "--list", "list_enabled", is_flag=True, help="List enabled applications"
)
@click.option(
    "-L",
    "--lock-code",
    metavar="HEX",
    help="Current application configuration lock code.",
)
def nfc(ctx, enable, disable, enable_all, disable_all, list_enabled, lock_code, force):
    """
    Enable or disable applications over NFC.
    """
    _require_config(ctx)

    if not (list_enabled or enable_all or enable or disable_all or disable):
        ctx.fail("No configuration options chosen.")

    info = ctx.obj["info"]
    nfc_supported = info.supported_capabilities.get(TRANSPORT.NFC)
    nfc_enabled = info.config.enabled_capabilities.get(TRANSPORT.NFC)

    if enable_all:
        enable = [c for c in CAPABILITY if c in nfc_supported]

    if disable_all:
        disable = [c for c in CAPABILITY if c in nfc_enabled]

    _ensure_not_invalid_options(ctx, enable, disable)

    if not nfc_supported:
        cli_fail("NFC not available on this YubiKey.")

    if list_enabled:
        _list_apps(ctx, nfc_enabled)

    for app in enable:
        if app & nfc_supported:
            nfc_enabled |= app
        else:
            cli_fail(f"{app.name} not supported over NFC on this YubiKey.")
    for app in disable:
        if app & nfc_supported:
            nfc_enabled &= ~app
        else:
            cli_fail(f"{app.name} not supported over NFC on this YubiKey.")

    f_confirm = ""
    if enable:
        f_confirm += f"Enable {', '.join(str(app) for app in enable)}.\n"
    if disable:
        f_confirm += f"Disable {', '.join(str(app) for app in disable)}.\n"
    f_confirm += "Configure NFC?"

    is_locked = info.is_locked

    if force and is_locked and not lock_code:
        cli_fail("Configuration is locked - please supply the --lock-code option.")
    if lock_code and not is_locked:
        cli_fail("Configuration is not locked - please remove the --lock-code option.")

    force or click.confirm(f_confirm, abort=True, err=True)

    if is_locked and not lock_code:
        lock_code = prompt_lock_code()

    if lock_code:
        lock_code = _parse_lock_code(ctx, lock_code)

    app = ctx.obj["controller"]
    try:
        app.write_device_config(
            DeviceConfig({TRANSPORT.NFC: nfc_enabled}, None, None, None),
            False,  # No need to reboot for NFC.
            lock_code,
        )
    except Exception as e:
        logger.error("Failed to write config", exc_info=e)
        cli_fail("Failed to configure NFC applications.")


def _list_apps(ctx, enabled):
    for app in CAPABILITY:
        if app & enabled:
            click.echo(str(app))
    ctx.exit()


def _ensure_not_invalid_options(ctx, enable, disable):
    if any(a in enable for a in disable):
        ctx.fail("Invalid options.")


def _parse_lock_code(ctx, lock_code):
    try:
        lock_code = bytes.fromhex(lock_code)
        if lock_code and len(lock_code) != 16:
            ctx.fail("Lock code must be exactly 16 bytes (32 hexadecimal digits) long.")
        return lock_code
    except Exception:
        ctx.fail("Lock code has the wrong format.")


# MODE


def _parse_interface_string(interface):
    for iface in USB_INTERFACE:
        if iface.name.startswith(interface):
            return iface
    raise ValueError()


def _parse_mode_string(ctx, param, mode):
    try:
        mode_int = int(mode)
        return Mode.from_code(mode_int)
    except IndexError:
        ctx.fail(f"Invalid mode: {mode_int}")
    except ValueError:
        pass  # Not a numeric mode, parse string

    try:
        interfaces = USB_INTERFACE(0)
        if mode[0] in ["+", "-"]:
            info = ctx.obj["info"]
            usb_enabled = info.config.enabled_capabilities[TRANSPORT.USB]
            my_mode = _mode_from_usb_enabled(usb_enabled)
            interfaces |= my_mode.interfaces
            for mod in re.findall(r"[+-][A-Z]+", mode.upper()):
                interface = _parse_interface_string(mod[1:])
                if mod.startswith("+"):
                    interfaces |= interface
                else:
                    interfaces ^= interface
        else:
            for t in filter(None, re.split(r"[+]+", mode.upper())):
                interfaces |= _parse_interface_string(t)
    except ValueError:
        ctx.fail(f"Invalid mode string: {mode}")

    return Mode(interfaces)


def _mode_from_usb_enabled(usb_enabled):
    interfaces = USB_INTERFACE(0)
    if CAPABILITY.OTP & usb_enabled:
        interfaces |= USB_INTERFACE.OTP
    if (CAPABILITY.U2F | CAPABILITY.FIDO2) & usb_enabled:
        interfaces |= USB_INTERFACE.FIDO
    if (CAPABILITY.OPENPGP | CAPABILITY.PIV | CAPABILITY.OATH) & usb_enabled:
        interfaces |= USB_INTERFACE.CCID
    return Mode(interfaces)


@config.command()
@click.argument("mode", callback=_parse_mode_string)
@click.option(
    "--touch-eject",
    is_flag=True,
    help="When set, the button "
    "toggles the state of the smartcard between ejected and inserted "
    "(CCID mode only).",
)
@click.option(
    "--autoeject-timeout",
    required=False,
    type=int,
    default=0,
    metavar="SECONDS",
    help="When set, the smartcard will automatically eject after the "
    "given time. Implies --touch-eject (CCID mode only).",
)
@click.option(
    "--chalresp-timeout",
    required=False,
    type=int,
    default=0,
    metavar="SECONDS",
    help="Sets the timeout when waiting for touch for challenge response.",
)
@click_force_option
@click.pass_context
def mode(ctx, mode, touch_eject, autoeject_timeout, chalresp_timeout, force):
    """
    Manage connection modes (USB Interfaces).

    This command is generaly used with YubiKeys prior to the 5 series.
    Use "ykman config usb" for more granular control on YubiKey 5 and later.

    Get the current connection mode of the YubiKey, or set it to MODE.

    MODE can be a string, such as "OTP+FIDO+CCID", or a shortened form: "o+f+c".
    It can also be a mode number.

    Examples:

    \b
      Set the OTP and FIDO mode:
      $ ykman config mode OTP+FIDO

    \b
      Set the CCID only mode and use touch to eject the smart card:
      $ ykman config mode CCID --touch-eject
    """
    info = ctx.obj["info"]
    mgmt = ctx.obj["controller"]
    usb_enabled = info.config.enabled_capabilities[TRANSPORT.USB]
    my_mode = _mode_from_usb_enabled(usb_enabled)
    usb_supported = info.supported_capabilities[TRANSPORT.USB]
    interfaces_supported = _mode_from_usb_enabled(usb_supported).interfaces
    pid = ctx.obj["pid"]
    if pid:
        key_type = pid.get_type()
    else:
        key_type = None

    if autoeject_timeout:
        touch_eject = True
    autoeject = autoeject_timeout if touch_eject else 0

    if mode.interfaces != USB_INTERFACE.CCID:
        if touch_eject:
            ctx.fail("--touch-eject can only be used when setting CCID-only mode")

    if not force:
        if mode == my_mode:
            cli_fail(f"Mode is already {mode}, nothing to do...", 0)
        elif key_type in (YUBIKEY.YKS, YUBIKEY.YKP):
            cli_fail(
                "Mode switching is not supported on this YubiKey!\n"
                "Use --force to attempt to set it anyway."
            )
        elif mode.interfaces not in interfaces_supported:
            cli_fail(
                f"Mode {mode} is not supported on this YubiKey!\n"
                + "Use --force to attempt to set it anyway."
            )
        force or click.confirm(f"Set mode of YubiKey to {mode}?", abort=True, err=True)

    try:
        mgmt.set_mode(mode, chalresp_timeout, autoeject)
        click.echo(
            "Mode set! You must remove and re-insert your YubiKey "
            "for this change to take effect."
        )
    except Exception as e:
        logger.debug("Failed to switch mode", exc_info=e)
        click.echo(
            "Failed to switch mode on the YubiKey. Make sure your "
            "YubiKey does not have an access code set."
        )
