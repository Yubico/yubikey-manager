//! PIV helpers for generating CHUIDs and maintaining pivman management-key metadata.
//!
//! These utilities build on [`PivSession`](crate::piv::PivSession). Missing
//! pivman objects are returned as empty entry lists; other read and parsing
//! errors are propagated.

use crate::__internal::tlv::{parse_tlv_list, tlv_encode, tlv_parse, tlv_unpack};
use crate::piv::{Chuid, FascN, ManagementKey, ManagementKeyType, ObjectId, PivError, PivSession};
use crate::smartcard::{SmartCardConnection, SmartCardError, Sw};

const PIVMAN_OBJ_ID: u32 = 0x5FFF00;
const PIVMAN_PROTECTED_OBJ_ID: u32 = ObjectId::Printed as u32;

const TAG_PIVMAN_DATA: u32 = 0x80;
const TAG_PIVMAN_FLAGS: u32 = 0x81;
const TAG_PIVMAN_PROTECTED: u32 = 0x88;
/// Tag containing the management key in the protected pivman object.
pub const TAG_PIVMAN_KEY: u32 = 0x89;

const PIVMAN_FLAG_KEY_PROTECTED: u8 = 0x02;

/// Generate a CHUID (Cardholder Unique Identifier).
///
/// Uses a Non-Federal Issuer FASC-N, a random (version 4) GUID, and a fixed 2030-01-01 expiry.
pub fn generate_chuid() -> Result<Chuid, PivError> {
    let mut guid = [0u8; 16];
    getrandom::fill(&mut guid).map_err(|e| PivError::InvalidData(format!("RNG error: {e}")))?;
    // Set the UUID version (4) and variant bits
    guid[6] = (guid[6] & 0x0f) | 0x40;
    guid[8] = (guid[8] & 0x3f) | 0x80;

    Ok(Chuid {
        buffer_length: None,
        // Non-Federal Issuer FASC-N.
        fasc_n: FascN {
            agency_code: 9999,
            system_code: 9999,
            credential_number: 999999,
            credential_series: 0,
            individual_credential_issue: 1,
            person_identifier: 0,
            organizational_category: 3,
            organizational_identifier: 0,
            organization_association_category: 1,
        },
        agency_code: None,
        organizational_identifier: None,
        duns: None,
        guid: guid.to_vec(),
        // Expires on: 2030-01-01
        expiration_date: (2030, 1, 1),
        authentication_key_map: None,
        asymmetric_signature: Vec::new(),
        lrc: None,
    })
}

/// Read the pivman public data object.
///
/// Returns the inner TLV list, or an empty list if the object is missing.
/// Other read errors and malformed metadata are returned as errors.
pub fn get_pivman_data(
    session: &mut PivSession<impl SmartCardConnection>,
) -> Result<Vec<(u32, Vec<u8>)>, PivError> {
    let entries = get_pivman_object(session, PIVMAN_OBJ_ID, TAG_PIVMAN_DATA)?;
    for (tag, value) in &entries {
        if *tag == TAG_PIVMAN_FLAGS && value.len() != 1 {
            return Err(PivError::InvalidData(format!(
                "Invalid pivman field 0x{tag:02x}: expected 1 byte"
            )));
        }
    }
    Ok(entries)
}

fn get_pivman_object(
    session: &mut PivSession<impl SmartCardConnection>,
    object_id: u32,
    tag: u32,
) -> Result<Vec<(u32, Vec<u8>)>, PivError> {
    log::debug!("Reading pivman object 0x{object_id:x}");
    let raw = match session.get_object_raw(object_id) {
        Ok(raw) => raw,
        Err(PivError::Connection(SmartCardError::Apdu { sw, .. }))
            if sw == Sw::FileNotFound as u16 =>
        {
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };
    let (_, _, _, end) = tlv_parse(&raw, 0)?;
    if end != raw.len() {
        return Err(PivError::InvalidData(format!(
            "Trailing data in pivman object 0x{object_id:x}"
        )));
    }
    Ok(parse_tlv_list(&tlv_unpack(tag, &raw)?)?)
}

/// Check if the management key is marked as stored on the device.
pub fn has_stored_key(pivman: &[(u32, Vec<u8>)]) -> bool {
    pivman
        .iter()
        .rfind(|(t, _)| *t == TAG_PIVMAN_FLAGS)
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
/// empty list if the object is missing. Other read and parsing errors are
/// returned as errors.
pub fn get_pivman_protected_data(
    session: &mut PivSession<impl SmartCardConnection>,
) -> Result<Vec<(u32, Vec<u8>)>, PivError> {
    get_pivman_object(session, PIVMAN_PROTECTED_OBJ_ID, TAG_PIVMAN_PROTECTED)
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
///
/// Requires management-key authentication. Storing the key also requires PIN
/// verification and readable protected metadata before the key is changed.
/// Public metadata is written only when its contents change. When switching
/// away from a stored key, inaccessible protected metadata and APDU errors
/// deleting the old key are logged but do not prevent the change.
///
/// Metadata write errors can occur after the management key has changed.
pub fn pivman_set_mgm_key(
    session: &mut PivSession<impl SmartCardConnection>,
    key_type: ManagementKeyType,
    new_key: &[u8],
    touch: bool,
    store_on_device: bool,
) -> Result<(), PivError> {
    let management_key = ManagementKey::new(key_type, new_key)?;
    let mut pivman = get_pivman_data(session)?;
    let original_pivman = pivman.clone();
    let was_stored = has_stored_key(&pivman);

    let mut prot = if store_on_device || was_stored {
        match get_pivman_protected_data(session) {
            Ok(data) => Some(data),
            Err(e) if !store_on_device => {
                log::debug!("Cannot read old protected pivman data: {e}");
                None
            }
            Err(e) => return Err(e),
        }
    } else {
        None
    };

    session.set_management_key(&management_key, touch)?;

    let current_flags = pivman
        .iter()
        .rfind(|(t, _)| *t == TAG_PIVMAN_FLAGS)
        .map(|(_, v)| if v.is_empty() { 0u8 } else { v[0] })
        .unwrap_or(0);

    let new_flags = if store_on_device {
        current_flags | PIVMAN_FLAG_KEY_PROTECTED
    } else {
        current_flags & !PIVMAN_FLAG_KEY_PROTECTED
    };

    if new_flags != current_flags {
        let value = (new_flags != 0).then(|| vec![new_flags]);
        set_tlv_entry(&mut pivman, TAG_PIVMAN_FLAGS, value);
    }

    if pivman != original_pivman {
        put_pivman_data(session, &pivman)?;
    }

    if let Some(ref mut prot_entries) = prot {
        if store_on_device {
            set_tlv_entry(prot_entries, TAG_PIVMAN_KEY, Some(new_key.to_vec()));
            put_pivman_protected_data(session, prot_entries)?;
        } else if prot_entries
            .iter()
            .rfind(|(tag, _)| *tag == TAG_PIVMAN_KEY)
            .is_some_and(|(_, value)| !value.is_empty())
        {
            set_tlv_entry(prot_entries, TAG_PIVMAN_KEY, None);
            match put_pivman_protected_data(session, prot_entries) {
                Ok(()) => {}
                Err(PivError::Connection(SmartCardError::Apdu { sw, .. })) => {
                    log::debug!("Cannot delete old protected management key: SW=0x{sw:04x}");
                }
                Err(e) => return Err(e),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Connection, Transport};
    use std::collections::VecDeque;

    type Response = Result<(Vec<u8>, u16), SmartCardError>;

    struct MockConnection {
        steps: VecDeque<(u8, Response)>,
        sent: Vec<Vec<u8>>,
    }

    impl Connection for MockConnection {
        type Error = SmartCardError;

        fn close(&mut self) {}
    }

    impl SmartCardConnection for MockConnection {
        fn send_and_receive(&mut self, apdu: &[u8]) -> Response {
            let (instruction, response) = self.steps.pop_front().expect("unexpected APDU");
            assert_eq!(apdu[1], instruction);
            self.sent.push(apdu.to_vec());
            response
        }

        fn transport(&self) -> Transport {
            Transport::Usb
        }
    }

    fn session(steps: Vec<(u8, Response)>) -> PivSession<MockConnection> {
        let mut init = VecDeque::from([
            (0xa4, Ok((vec![], Sw::Ok as u16))),
            (0xfd, Ok((vec![5, 4, 0], Sw::Ok as u16))),
            (0xf7, Ok((vec![1, 1, 3, 2, 2, 0, 1], Sw::Ok as u16))),
        ]);
        init.extend(steps);
        match PivSession::new(MockConnection {
            steps: init,
            sent: Vec::new(),
        }) {
            Ok(session) => session,
            Err((error, _)) => panic!("Failed to initialize mock session: {error}"),
        }
    }

    fn object(tag: u32, entries: &[(u32, Vec<u8>)]) -> Response {
        let inner: Vec<u8> = entries
            .iter()
            .flat_map(|(tag, value)| tlv_encode(*tag, value))
            .collect();
        Ok((tlv_encode(0x53, &tlv_encode(tag, &inner)), Sw::Ok as u16))
    }

    fn done(session: PivSession<MockConnection>) -> MockConnection {
        let connection = session.into_connection();
        assert!(connection.steps.is_empty());
        connection
    }

    #[test]
    fn readers_only_treat_missing_objects_as_empty() {
        for protected in [false, true] {
            for sw in [Sw::FileNotFound as u16, 0x6982, 0x6a80] {
                let mut session = session(vec![(0xcb, Ok((vec![], sw)))]);
                let result = if protected {
                    get_pivman_protected_data(&mut session)
                } else {
                    get_pivman_data(&mut session)
                };
                if sw == Sw::FileNotFound as u16 {
                    assert!(result.unwrap().is_empty());
                } else {
                    assert!(matches!(
                        result,
                        Err(PivError::Connection(SmartCardError::Apdu { sw: actual, .. }))
                            if actual == sw
                    ));
                }
                done(session);
            }
            let mut session = session(vec![(
                0xcb,
                Err(SmartCardError::Transport(Box::new(std::io::Error::other(
                    "disconnected",
                )))),
            )]);
            let result = if protected {
                get_pivman_protected_data(&mut session)
            } else {
                get_pivman_data(&mut session)
            };
            assert!(matches!(
                result,
                Err(PivError::Connection(SmartCardError::Transport(_)))
            ));
            done(session);
        }
    }

    #[test]
    fn readers_reject_malformed_metadata() {
        for protected in [false, true] {
            let tag = if protected {
                TAG_PIVMAN_PROTECTED
            } else {
                TAG_PIVMAN_DATA
            };
            for raw in [
                vec![],
                tlv_encode(0x90, &[]),
                tlv_encode(tag, &[0x81, 2, 1]),
                [tlv_encode(tag, &[]), tlv_encode(0x90, &[])].concat(),
            ] {
                let mut session =
                    session(vec![(0xcb, Ok((tlv_encode(0x53, &raw), Sw::Ok as u16)))]);
                let result = if protected {
                    get_pivman_protected_data(&mut session)
                } else {
                    get_pivman_data(&mut session)
                };
                assert!(matches!(result, Err(PivError::InvalidData(_))));
                done(session);
            }
        }
        for (tag, value) in [(0x81, vec![]), (0x81, vec![1, 2])] {
            let mut session = session(vec![(0xcb, object(TAG_PIVMAN_DATA, &[(tag, value)]))]);
            assert!(matches!(
                get_pivman_data(&mut session),
                Err(PivError::InvalidData(_))
            ));
            done(session);
        }
    }

    #[test]
    fn legacy_fields_are_preserved_without_interpretation() {
        for value in [vec![], vec![1], vec![1; 4], vec![1; 16]] {
            let entries = vec![
                (TAG_PIVMAN_FLAGS, vec![1]),
                (0x82, value.clone()),
                (0x83, value),
            ];
            let mut session = session(vec![(0xcb, object(TAG_PIVMAN_DATA, &entries))]);
            let actual = get_pivman_data(&mut session).unwrap();
            assert_eq!(actual, entries);
            assert!(!has_stored_key(&actual));
            done(session);
        }
    }

    #[test]
    fn storing_requires_readable_protected_metadata_before_changing_key() {
        let mut session = session(vec![
            (0xcb, object(TAG_PIVMAN_DATA, &[])),
            (0xcb, Ok((vec![], 0x6982))),
        ]);
        let result = pivman_set_mgm_key(
            &mut session,
            ManagementKeyType::Aes256,
            &[1; 32],
            false,
            true,
        );
        assert!(matches!(
            result,
            Err(PivError::Connection(SmartCardError::Apdu { .. }))
        ));
        assert_eq!(session.management_key_type(), ManagementKeyType::Tdes);
        done(session);
    }

    #[test]
    fn unchanged_public_metadata_is_not_written_or_reordered() {
        let mut session = session(vec![
            (
                0xcb,
                object(TAG_PIVMAN_DATA, &[(0x81, vec![1]), (0x90, vec![7])]),
            ),
            (0xff, Ok((vec![], Sw::Ok as u16))),
        ]);
        pivman_set_mgm_key(
            &mut session,
            ManagementKeyType::Aes256,
            &[1; 32],
            true,
            false,
        )
        .unwrap();
        assert_eq!(session.management_key_type(), ManagementKeyType::Aes256);
        let connection = done(session);
        assert_eq!(connection.sent.last().unwrap()[3], 0xfe);
    }

    #[test]
    fn switching_away_from_stored_key_allows_inaccessible_protected_data() {
        let mut session = session(vec![
            (0xcb, object(TAG_PIVMAN_DATA, &[(0x81, vec![2])])),
            (0xcb, Ok((vec![], 0x6982))),
            (0xff, Ok((vec![], Sw::Ok as u16))),
            (0xdb, Ok((vec![], Sw::Ok as u16))),
        ]);
        pivman_set_mgm_key(
            &mut session,
            ManagementKeyType::Aes256,
            &[1; 32],
            false,
            false,
        )
        .unwrap();
        done(session);
    }

    #[test]
    fn clearing_old_key_tolerates_apdu_errors_but_propagates_transport_errors() {
        for transport_error in [false, true] {
            let cleanup = if transport_error {
                Err(SmartCardError::Transport(Box::new(std::io::Error::other(
                    "disconnected",
                ))))
            } else {
                Ok((vec![], 0x6982))
            };
            let mut session = session(vec![
                (0xcb, object(TAG_PIVMAN_DATA, &[(0x81, vec![2])])),
                (
                    0xcb,
                    object(TAG_PIVMAN_PROTECTED, &[(TAG_PIVMAN_KEY, vec![1; 24])]),
                ),
                (0xff, Ok((vec![], Sw::Ok as u16))),
                (0xdb, Ok((vec![], Sw::Ok as u16))),
                (0xdb, cleanup),
            ]);
            let result = pivman_set_mgm_key(
                &mut session,
                ManagementKeyType::Aes256,
                &[1; 32],
                false,
                false,
            );
            if transport_error {
                assert!(matches!(
                    result,
                    Err(PivError::Connection(SmartCardError::Transport(_)))
                ));
            } else {
                result.unwrap();
            }
            assert_eq!(session.management_key_type(), ManagementKeyType::Aes256);
            done(session);
        }
    }

    #[test]
    fn generated_chuid_uses_non_federal_identity_and_uuid_v4() {
        let chuid = generate_chuid().unwrap();
        assert_eq!(
            chuid.fasc_n,
            FascN {
                agency_code: 9999,
                system_code: 9999,
                credential_number: 999999,
                credential_series: 0,
                individual_credential_issue: 1,
                person_identifier: 0,
                organizational_category: 3,
                organizational_identifier: 0,
                organization_association_category: 1,
            }
        );
        assert_eq!(chuid.expiration_date, (2030, 1, 1));
        assert!(chuid.asymmetric_signature.is_empty());
        assert_eq!(chuid.guid.len(), 16);
        assert_eq!(chuid.guid[6] >> 4, 4);
        assert_eq!(chuid.guid[8] & 0xc0, 0x80);
        assert_eq!(Chuid::from_bytes(&chuid.to_bytes()).unwrap(), chuid);
        let other = generate_chuid().unwrap();
        assert_ne!(chuid.guid, other.guid);
    }

    #[test]
    fn stored_key_flag_ignores_other_flags_and_missing_values() {
        assert!(!has_stored_key(&[]));
        assert!(!has_stored_key(&[(TAG_PIVMAN_FLAGS, vec![])]));
        assert!(!has_stored_key(&[(TAG_PIVMAN_FLAGS, vec![0x01])]));
        assert!(!has_stored_key(&[(0x82, vec![1; 16])]));
        assert!(has_stored_key(&[(TAG_PIVMAN_FLAGS, vec![0x02])]));
        assert!(has_stored_key(&[(TAG_PIVMAN_FLAGS, vec![0x03])]));
        assert!(!has_stored_key(&[
            (TAG_PIVMAN_FLAGS, vec![0x02]),
            (TAG_PIVMAN_FLAGS, vec![0x01]),
        ]));
    }

    #[test]
    fn updating_tlv_entries_preserves_unrelated_metadata() {
        let mut entries = vec![
            (0x90, vec![1, 2]),
            (TAG_PIVMAN_FLAGS, vec![0x01]),
            (TAG_PIVMAN_FLAGS, vec![0x02]),
        ];
        set_tlv_entry(&mut entries, TAG_PIVMAN_FLAGS, Some(vec![0x03]));
        assert_eq!(
            entries,
            vec![(0x90, vec![1, 2]), (TAG_PIVMAN_FLAGS, vec![0x03])]
        );
        set_tlv_entry(&mut entries, TAG_PIVMAN_FLAGS, None);
        assert_eq!(entries, vec![(0x90, vec![1, 2])]);
    }
}
