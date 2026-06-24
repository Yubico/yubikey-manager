use yubikit::piv::{ManagementKey, ManagementKeyType, ObjectId, PivError, PivSession};
use yubikit::smartcard::SmartCardConnection;
use yubikit::tlv::{parse_tlv_list, tlv_encode, tlv_unpack};

const PIVMAN_OBJ_ID: u32 = 0x5FFF00;
const PIVMAN_PROTECTED_OBJ_ID: u32 = ObjectId::Printed as u32;

const TAG_PIVMAN_DATA: u32 = 0x80;
const TAG_PIVMAN_FLAGS: u32 = 0x81;
pub const TAG_PIVMAN_SALT: u32 = 0x82;
const TAG_PIVMAN_PROTECTED: u32 = 0x88;
pub const TAG_PIVMAN_KEY: u32 = 0x89;

const PIVMAN_FLAG_KEY_PROTECTED: u8 = 0x02;

/// Read the pivman public data object.
///
/// Returns the inner TLV list, or an empty list if the object is not present or
/// is malformed.
pub fn get_pivman_data(session: &mut PivSession<impl SmartCardConnection>) -> Vec<(u32, Vec<u8>)> {
    session
        .get_object_raw(PIVMAN_OBJ_ID)
        .ok()
        .and_then(|raw| {
            let inner = tlv_unpack(TAG_PIVMAN_DATA, &raw).ok()?;
            parse_tlv_list(&inner).ok()
        })
        .unwrap_or_default()
}

/// Check if the management key is marked as stored on the device.
pub fn has_stored_key(pivman: &[(u32, Vec<u8>)]) -> bool {
    pivman
        .iter()
        .find(|(t, _)| *t == TAG_PIVMAN_FLAGS)
        .is_some_and(|(_, v)| !v.is_empty() && (v[0] & PIVMAN_FLAG_KEY_PROTECTED) != 0)
}

fn put_pivman_data(
    session: &mut PivSession<impl SmartCardConnection>,
    entries: &[(u32, Vec<u8>)],
) -> Result<(), PivError> {
    let mut inner = Vec::new();
    for (tag, val) in entries {
        inner.extend_from_slice(&tlv_encode(*tag, val));
    }
    let outer = if inner.is_empty() {
        vec![]
    } else {
        tlv_encode(TAG_PIVMAN_DATA, &inner)
    };
    session.put_object_raw(PIVMAN_OBJ_ID, Some(&outer))
}

/// Read the pivman protected data object.
///
/// Requires PIN verification before use. Returns the inner TLV list, or an
/// empty list if the object is not present or is malformed.
pub fn get_pivman_protected_data(
    session: &mut PivSession<impl SmartCardConnection>,
) -> Vec<(u32, Vec<u8>)> {
    session
        .get_object_raw(PIVMAN_PROTECTED_OBJ_ID)
        .ok()
        .and_then(|raw| {
            let inner = tlv_unpack(TAG_PIVMAN_PROTECTED, &raw).ok()?;
            parse_tlv_list(&inner).ok()
        })
        .unwrap_or_default()
}

fn put_pivman_protected_data(
    session: &mut PivSession<impl SmartCardConnection>,
    entries: &[(u32, Vec<u8>)],
) -> Result<(), PivError> {
    let mut inner = Vec::new();
    for (tag, val) in entries {
        inner.extend_from_slice(&tlv_encode(*tag, val));
    }
    let outer = if inner.is_empty() {
        vec![]
    } else {
        tlv_encode(TAG_PIVMAN_PROTECTED, &inner)
    };
    session.put_object_raw(PIVMAN_PROTECTED_OBJ_ID, Some(&outer))
}

fn set_tlv_entry(entries: &mut Vec<(u32, Vec<u8>)>, tag: u32, value: Option<Vec<u8>>) {
    entries.retain(|(t, _)| *t != tag);
    if let Some(v) = value {
        entries.push((tag, v));
    }
}

/// Set the management key and keep pivman data in sync.
pub fn pivman_set_mgm_key(
    session: &mut PivSession<impl SmartCardConnection>,
    key_type: ManagementKeyType,
    new_key: &[u8],
    touch: bool,
    store_on_device: bool,
) -> Result<(), PivError> {
    let mut pivman = get_pivman_data(session);
    let was_stored = has_stored_key(&pivman);

    let mut prot = if store_on_device || was_stored {
        Some(get_pivman_protected_data(session))
    } else {
        None
    };

    let management_key = ManagementKey::new(key_type, new_key)?;
    session.set_management_key(&management_key, touch)?;

    let current_flags = pivman
        .iter()
        .find(|(t, _)| *t == TAG_PIVMAN_FLAGS)
        .map(|(_, v)| if v.is_empty() { 0u8 } else { v[0] })
        .unwrap_or(0);

    let new_flags = if store_on_device {
        current_flags | PIVMAN_FLAG_KEY_PROTECTED
    } else {
        current_flags & !PIVMAN_FLAG_KEY_PROTECTED
    };

    if new_flags != 0 {
        set_tlv_entry(&mut pivman, TAG_PIVMAN_FLAGS, Some(vec![new_flags]));
    } else {
        set_tlv_entry(&mut pivman, TAG_PIVMAN_FLAGS, None);
    }

    put_pivman_data(session, &pivman)?;

    if let Some(ref mut prot_entries) = prot {
        if store_on_device {
            set_tlv_entry(prot_entries, TAG_PIVMAN_KEY, Some(new_key.to_vec()));
        } else {
            set_tlv_entry(prot_entries, TAG_PIVMAN_KEY, None);
        }
        put_pivman_protected_data(session, prot_entries)?;
    }

    Ok(())
}
