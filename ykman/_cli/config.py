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

from yubikit.core import TRANSPORT, YUBIKEY
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.management import (
    ManagementSession,
    DeviceConfig,
    CAPABILITY,
    USB_INTERFACE,
    DEVICE_FLAG,
    FORM_FACTOR,
    Mode,
)
from .util import (
    click_group,
    click_postpone_execution,
    click_force_option,
    click_prompt,
    EnumChoice,
    CliFail,
)
import os
import re
import sys
import click
import logging


logger = logging.getLogger(__name__)


CLEAR_LOCK_CODE = b"\0" * 16


def prompt_lock_code():
    return click_prompt("Enter your lock code", hide_input=True)


@click_group(connections=[SmartCardConnection, OtpConnection, FidoConnection])
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
    dev = ctx.obj["device"]
    for conn_type in (SmartCardConnection, OtpConnection, FidoConnection):
        if dev.supports_connection(conn_type):
            try:
                conn = dev.open_connection(conn_type)
                ctx.call_on_close(conn.close)
                ctx.obj["session"] = ManagementSession(conn)
                return
            except Exception:
                logger.warning(
                    f"Failed connecting to the YubiKey over {conn_type}", exc_info=True
                )
    raise CliFail("Couldn't connect to the YubiKey.")


def _require_config(ctx):
    info = ctx.obj["info"]
    if (1, 0, 0) < info.version < (5, 0, 0):
        raise CliFail(
            "Configuring applications is not supported on this YubiKey. "
            "Use the `mode` command to configure USB interfaces."
        )


@config.command(hidden="--full-help" not in sys.argv)
@click.pass_context
@click_force_option
def reset(ctx, force):
    """
    Reset all YubiKey data.

    This action will wipe all data and restore factory settings for
    all applications on the YubiKey.
    """
    transport = ctx.obj["device"].transport
    info = ctx.obj["info"]
    is_bio = info.form_factor in (FORM_FACTOR.USB_A_BIO, FORM_FACTOR.USB_C_BIO)
    has_piv = CAPABILITY.PIV in info.supported_capabilities.get(transport)
    if not (is_bio and has_piv):
        raise CliFail("Full device reset is not supported on this YubiKey.")

    force or click.confirm(
        "WARNING! This will delete all stored data and restore factory "
        "settings. Proceed?",
        abort=True,
        err=True,
    )

    click.echo("Resetting YubiKey data...")
    ctx.obj["session"].device_reset()

    click.echo("Success! All data have been cleared from the YubiKey.")


@config.command("set-lock-code")
@click.pass_context
@click_force_option
@click.option("-l", "--lock-code", metavar="HEX", help="current lock code")
@click.option(
    "-n",
    "--new-lock-code",
    metavar="HEX",
    help="new lock code (can't be used with --generate)",
)
@click.option("-c", "--clear", is_flag=True, help="clear the lock code")
@click.option(
    "-g",
    "--generate",
    is_flag=True,
    help="generate a random lock code (can't be used with --new-lock-code)",
)
def set_lock_code(ctx, lock_code, new_lock_code, clear, generate, force):
    """
    Set or change the configuration lock code.

    A lock code may be used to protect the application configuration.
    The lock code must be a 32 characters (16 bytes) hex value.
    """

    _require_config(ctx)
    info = ctx.obj["info"]
    app = ctx.obj["session"]

    if sum(1 for arg in [new_lock_code, generate, clear] if arg) > 1:
        raise CliFail(
            "Invalid options: Only one of --new-lock-code, --generate, "
            "and --clear may be used."
        )

    # Get the new lock code to set
    if clear:
        set_code = CLEAR_LOCK_CODE
    elif generate:
        set_code = os.urandom(16)
        click.echo(f"Using a randomly generated lock code: {set_code.hex()}")
        force or click.confirm(
            "Lock configuration with this lock code?", abort=True, err=True
        )
    else:
        if not new_lock_code:
            new_lock_code = click_prompt(
                "Enter your new lock code", hide_input=True, confirmation_prompt=True
            )
        set_code = _parse_lock_code(ctx, new_lock_code)

    # Get the current lock code to use
    if info.is_locked:
        if not lock_code:
            lock_code = click_prompt("Enter your current lock code", hide_input=True)
        use_code = _parse_lock_code(ctx, lock_code)
    else:
        if lock_code:
            raise CliFail(
                "No lock code is currently set. Use --new-lock-code to set one."
            )
        use_code = None

    # Set new lock code
    try:
        app.write_device_config(
            None,
            False,
            use_code,
            set_code,
        )
        logger.info("Lock code updated")
    except Exception:
        if info.is_locked:
            raise CliFail("Failed to change the lock code. Wrong current code?")
        raise CliFail("Failed to set the lock code.")


def _configure_applications(
    ctx,
    config,
    changes,
    transport,
    enable,
    disable,
    lock_code,
    force,
):
    _require_config(ctx)

    info = ctx.obj["info"]
    supported = info.supported_capabilities.get(transport)
    enabled = info.config.enabled_capabilities.get(transport)

    if not supported:
        raise CliFail(f"{transport} not supported on this YubiKey.")

    if enable & disable:
        ctx.fail("Invalid options.")

    unsupported = ~supported & (enable | disable)
    if unsupported:
        raise CliFail(
            f"{unsupported.display_name} not supported over {transport} on this "
            "YubiKey."
        )
    new_enabled = (enabled | enable) & ~disable

    if transport == TRANSPORT.USB:
        if sum(CAPABILITY) & new_enabled == 0:
            ctx.fail(f"Can not disable all applications over {transport}.")

        reboot = enabled.usb_interfaces != new_enabled.usb_interfaces
    else:
        reboot = False

    if enable:
        changes.append(f"Enable {enable.display_name}")
    if disable:
        changes.append(f"Disable {disable.display_name}")
    if reboot:
        changes.append("The YubiKey will reboot")

    is_locked = info.is_locked

    if force and is_locked and not lock_code:
        raise CliFail("Configuration is locked - please supply the --lock-code option.")
    if lock_code and not is_locked:
        raise CliFail(
            "Configuration is not locked - please remove the --lock-code option."
        )

    click.echo(f"{transport} configuration changes:")
    for change in changes:
        click.echo(f"  {change}")
    force or click.confirm("Proceed?", abort=True, err=True)

    if is_locked and not lock_code:
        lock_code = prompt_lock_code()

    if lock_code:
        lock_code = _parse_lock_code(ctx, lock_code)

    config.enabled_capabilities = {transport: new_enabled}

    app = ctx.obj["session"]
    try:
        app.write_device_config(
            config,
            reboot,
            lock_code,
        )
        logger.info(f"{transport} application configuration updated")
    except Exception:
        raise CliFail(f"Failed to configure {transport} applications.")


@config.command()
@click.pass_context
@click_force_option
@click.option(
    "-e",
    "--enable",
    multiple=True,
    type=EnumChoice(CAPABILITY),
    help="enable applications",
)
@click.option(
    "-d",
    "--disable",
    multiple=True,
    type=EnumChoice(CAPABILITY),
    help="disable applications",
)
@click.option(
    "-l", "--list", "list_enabled", is_flag=True, help="list enabled applications"
)
@click.option("-a", "--enable-all", is_flag=True, help="enable all applications")
@click.option(
    "-L",
    "--lock-code",
    metavar="HEX",
    help="current application configuration lock code",
)
@click.option(
    "--touch-eject",
    is_flag=True,
    help="when set, the button toggles the state"
    " of the smartcard between ejected and inserted (CCID only)",
)
@click.option("--no-touch-eject", is_flag=True, help="disable touch eject (CCID only)")
@click.option(
    "--autoeject-timeout",
    required=False,
    type=int,
    default=None,
    metavar="SECONDS",
    help="when set, the smartcard will automatically eject"
    " after the given time (implies --touch-eject)",
)
@click.option(
    "--chalresp-timeout",
    required=False,
    type=int,
    default=None,
    metavar="SECONDS",
    help="sets the timeout when waiting for touch for challenge-response in the OTP "
    "application",
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

    if touch_eject and no_touch_eject:
        ctx.fail("Invalid options.")

    if list_enabled:
        _list_apps(ctx, TRANSPORT.USB)

    config = DeviceConfig({}, autoeject_timeout, chalresp_timeout, None)
    changes = []
    info = ctx.obj["info"]

    if enable_all:
        enable = info.supported_capabilities.get(TRANSPORT.USB)
    else:
        enable = CAPABILITY(sum(enable))
    disable = CAPABILITY(sum(disable))

    if touch_eject:
        config.device_flags = info.config.device_flags | DEVICE_FLAG.EJECT
        changes.append("Enable touch-eject")
    if no_touch_eject:
        config.device_flags = info.config.device_flags & ~DEVICE_FLAG.EJECT
        changes.append("Disable touch-eject")
    if autoeject_timeout:
        changes.append(f"Set auto-eject timeout to {autoeject_timeout}")
    if chalresp_timeout:
        changes.append(f"Set challenge-response timeout to {chalresp_timeout}")

    _configure_applications(
        ctx,
        config,
        changes,
        TRANSPORT.USB,
        enable,
        disable,
        lock_code,
        force,
    )


@config.command()
@click.pass_context
@click_force_option
@click.option(
    "-e",
    "--enable",
    multiple=True,
    type=EnumChoice(CAPABILITY),
    help="enable applications",
)
@click.option(
    "-d",
    "--disable",
    multiple=True,
    type=EnumChoice(CAPABILITY),
    help="disable applications",
)
@click.option("-a", "--enable-all", is_flag=True, help="enable all applications")
@click.option("-D", "--disable-all", is_flag=True, help="disable all applications")
@click.option(
    "-l", "--list", "list_enabled", is_flag=True, help="list enabled applications"
)
@click.option(
    "-L",
    "--lock-code",
    metavar="HEX",
    help="current application configuration lock code",
)
def nfc(ctx, enable, disable, enable_all, disable_all, list_enabled, lock_code, force):
    """
    Enable or disable applications over NFC.
    """
    _require_config(ctx)

    if not (list_enabled or enable_all or enable or disable_all or disable):
        ctx.fail("No configuration options chosen.")

    if list_enabled:
        _list_apps(ctx, TRANSPORT.NFC)

    config = DeviceConfig({}, None, None, None)
    info = ctx.obj["info"]

    nfc_supported = info.supported_capabilities.get(TRANSPORT.NFC)
    if enable_all:
        enable = nfc_supported
    else:
        enable = CAPABILITY(sum(enable))
    if disable_all:
        disable = nfc_supported
    else:
        disable = CAPABILITY(sum(disable))

    _configure_applications(
        ctx,
        config,
        [],
        TRANSPORT.NFC,
        enable,
        disable,
        lock_code,
        force,
    )


def _list_apps(ctx, transport):
    enabled = ctx.obj["info"].config.enabled_capabilities.get(transport)
    if enabled is None:
        raise CliFail(f"{transport} not supported on this YubiKey.")

    for app in CAPABILITY:
        if app & enabled:
            click.echo(app.display_name)
    ctx.exit()


def _ensure_not_invalid_options(ctx, enable, disable):
    if enable & disable:
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
        if (iface.name or "").startswith(interface):
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
        if mode[0] in ["+", "-"]:
            info = ctx.obj["info"]
            usb_enabled = info.config.enabled_capabilities[TRANSPORT.USB]
            interfaces = usb_enabled.usb_interfaces
            for mod in re.findall(r"[+-][A-Z]+", mode.upper()):
                interface = _parse_interface_string(mod[1:])
                if mod.startswith("+"):
                    interfaces |= interface
                else:
                    interfaces ^= interface
        else:
            interfaces = USB_INTERFACE(0)
            for t in re.split(r"[+]+", mode.upper()):
                if t:
                    interfaces |= _parse_interface_string(t)
    except ValueError:
        ctx.fail(f"Invalid mode string: {mode}")

    return Mode(interfaces)


@config.command()
@click.argument("mode", callback=_parse_mode_string)
@click.option(
    "--touch-eject",
    is_flag=True,
    help="when set, the button "
    "toggles the state of the smartcard between ejected and inserted "
    "(CCID only)",
)
@click.option(
    "--autoeject-timeout",
    required=False,
    type=int,
    default=0,
    metavar="SECONDS",
    help="when set, the smartcard will automatically eject after the given time "
    "(implies --touch-eject, CCID only)",
)
@click.option(
    "--chalresp-timeout",
    required=False,
    type=int,
    default=0,
    metavar="SECONDS",
    help="sets the timeout when waiting for touch for challenge response",
)
@click_force_option
@click.pass_context
def mode(ctx, mode, touch_eject, autoeject_timeout, chalresp_timeout, force):
    """
    Manage connection modes (USB Interfaces).

    This command is generally used with YubiKeys prior to the 5 series.
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
    mgmt = ctx.obj["session"]
    usb_enabled = info.config.enabled_capabilities[TRANSPORT.USB]
    my_mode = Mode(usb_enabled.usb_interfaces)
    usb_supported = info.supported_capabilities[TRANSPORT.USB]
    interfaces_supported = usb_supported.usb_interfaces
    pid = ctx.obj["pid"]
    if pid:
        key_type = pid.yubikey_type
    else:
        key_type = None

    if autoeject_timeout:  # autoeject implies touch eject
        touch_eject = True
    autoeject = autoeject_timeout if touch_eject else None

    if mode.interfaces != USB_INTERFACE.CCID:
        if touch_eject:
            ctx.fail("--touch-eject can only be used when setting CCID-only mode")

    if not force:
        if mode == my_mode:
            raise CliFail(f"Mode is already {mode}, nothing to do...", 0)
        elif key_type in (YUBIKEY.YKS, YUBIKEY.YKP):
            raise CliFail(
                "Mode switching is not supported on this YubiKey!\n"
                "Use --force to attempt to set it anyway."
            )
        elif mode.interfaces not in interfaces_supported:
            raise CliFail(
                f"Mode {mode} is not supported on this YubiKey!\n"
                + "Use --force to attempt to set it anyway."
            )
        force or click.confirm(f"Set mode of YubiKey to {mode}?", abort=True, err=True)

    try:
        mgmt.set_mode(mode, chalresp_timeout, autoeject)
        logger.info("USB mode updated")
        click.echo(
            "Mode set! You must remove and re-insert your YubiKey "
            "for this change to take effect."
        )
    except Exception:
        raise CliFail(
            "Failed to switch mode on the YubiKey. Make sure your "
            "YubiKey does not have an access code set."
        )
