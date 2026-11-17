//! Support for the YubiKey FIPS (4 Series).
//!
//! These devices predate the `fips_capable`/`fips_approved` fields of
//! [`DeviceInfo`] and instead expose FIPS approved mode and the FIDO U2F PIN
//! through vendor specific commands.

use anyhow::{Result, anyhow};
use std::thread::sleep;
use std::time::Duration;

use yubikit::core::Connection;
use yubikit::ctap::{CtapError, CtapSession};
use yubikit::management::DeviceInfo;
use yubikit::smartcard::{SmartCardError, Sw};
use yubikit::yubiotp::{ConfigSlot, YubiOtpError, YubiOtpSession};

const U2F_VENDOR_FIRST: u8 = 0x40;
const INS_FIPS_VERIFY_PIN: u8 = U2F_VENDOR_FIRST + 3;
const INS_FIPS_SET_PIN: u8 = U2F_VENDOR_FIRST + 4;
const INS_FIPS_RESET: u8 = U2F_VENDOR_FIRST + 5;
const INS_FIPS_VERIFY_FIPS_MODE: u8 = U2F_VENDOR_FIRST + 6;

const RESET_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The status word of a failed U2F command, if that is what `e` is.
pub fn apdu_sw(e: &anyhow::Error) -> Option<u16> {
    match e.downcast_ref::<SmartCardError>() {
        Some(SmartCardError::Apdu { sw, .. }) => Some(*sw),
        _ => None,
    }
}

/// Whether the device is a YubiKey FIPS (4 Series).
pub fn is_yk4_fips(info: &DeviceInfo) -> bool {
    info.version.0 == 4 && info.is_fips
}

/// Encode a U2F (CTAP1) APDU using extended length encoding.
fn encode_apdu(ins: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut apdu = vec![0, ins, 0, 0, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    apdu.extend_from_slice(data);
    apdu.extend_from_slice(&[0, 0]);
    apdu
}

fn send_apdu<C: Connection + 'static>(
    session: &mut CtapSession<C>,
    ins: u8,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut response = session.call_msg(&encode_apdu(ins, data))?;
    if response.len() < 2 {
        return Err(CtapError::<C::Error>::InvalidResponse("U2F response too short".into()).into());
    }
    let sw_bytes = response.split_off(response.len() - 2);
    match u16::from_be_bytes([sw_bytes[0], sw_bytes[1]]) {
        0x9000 => Ok(response),
        sw => Err(SmartCardError::Apdu { data: response, sw }.into()),
    }
}

/// Check if the FIDO U2F application of a YubiKey FIPS (4 Series) is in FIPS
/// approved mode (i.e. a U2F PIN is set).
pub fn is_in_fips_mode<C: Connection + 'static>(session: &mut CtapSession<C>) -> Result<bool> {
    match send_apdu(session, INS_FIPS_VERIFY_FIPS_MODE, &[]) {
        Ok(_) => Ok(true),
        Err(e) if apdu_sw(&e) == Some(Sw::FunctionNotSupported as u16) => Ok(false),
        Err(e) => Err(e),
    }
}

fn set_pin_data(old_pin: &str, new_pin: &str) -> Vec<u8> {
    let new_pin = new_pin.as_bytes();
    let mut data = Vec::with_capacity(1 + old_pin.len() + new_pin.len());
    data.push(new_pin.len() as u8);
    data.extend_from_slice(old_pin.as_bytes());
    data.extend_from_slice(new_pin);
    data
}

/// Set or change the FIDO U2F PIN of a YubiKey FIPS (4 Series).
///
/// Pass an empty `old_pin` if no PIN is currently set.
pub fn fips_change_pin<C: Connection + 'static>(
    session: &mut CtapSession<C>,
    old_pin: &str,
    new_pin: &str,
) -> Result<()> {
    send_apdu(session, INS_FIPS_SET_PIN, &set_pin_data(old_pin, new_pin)).map(|_| ())
}

/// Verify the FIDO U2F PIN of a YubiKey FIPS (4 Series), unlocking U2F
/// registration for the current session.
pub fn fips_verify_pin<C: Connection + 'static>(
    session: &mut CtapSession<C>,
    pin: &str,
) -> Result<()> {
    send_apdu(session, INS_FIPS_VERIFY_PIN, pin.as_bytes()).map(|_| ())
}

/// Reset the FIDO U2F application of a YubiKey FIPS (4 Series).
///
/// This also overwrites the U2F attestation key. It is only allowed shortly
/// after the YubiKey is powered up, and requires the user to touch the
/// YubiKey. `on_touch` is called once the device starts waiting for touch.
pub fn fips_reset<C: Connection + 'static>(
    session: &mut CtapSession<C>,
    on_touch: &mut dyn FnMut(),
    cancel: &dyn Fn() -> bool,
) -> Result<()> {
    let mut prompted = false;
    loop {
        match send_apdu(session, INS_FIPS_RESET, &[]) {
            Err(e) if apdu_sw(&e) == Some(Sw::ConditionsNotSatisfied as u16) => {
                if !prompted {
                    on_touch();
                    prompted = true;
                }
                if cancel() {
                    return Err(anyhow!("Reset aborted by user."));
                }
                sleep(RESET_POLL_INTERVAL);
            }
            result => return result.map(|_| ()),
        }
    }
}

/// Check if the OTP application of a YubiKey FIPS (4 Series) is in FIPS
/// approved mode.
pub fn otp_is_in_fips_mode<C: Connection + 'static>(
    session: &mut YubiOtpSession<C>,
) -> Result<bool, YubiOtpError<C::Error>> {
    Ok(session.send_and_receive(ConfigSlot::Yk4FipsMode, &[], 1)? == [1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_extended_length_apdu() {
        assert_eq!(
            encode_apdu(INS_FIPS_VERIFY_FIPS_MODE, &[]),
            [0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_apdu(INS_FIPS_VERIFY_PIN, b"123456"),
            b"\x00\x43\x00\x00\x00\x00\x06123456\x00\x00"
        );
    }

    #[test]
    fn set_pin_data_prefixes_new_pin_length() {
        assert_eq!(set_pin_data("", "123456"), b"\x06123456");
        assert_eq!(set_pin_data("123456", "abcdefg"), b"\x07123456abcdefg");
    }
}
