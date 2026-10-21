//! Validation of the input and output of PIV `calculate_secret`, which performs
//! both ECDH key agreement and ML-KEM decapsulation.

use subtle::ConstantTimeEq;

use crate::keys::{EcCurve, PublicKey};
use crate::piv::{KeyType, PivError};

/// Length of an ML-KEM shared secret (FIPS 203).
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;

/// Ciphertext length for an ML-KEM key type (FIPS 203), or `None` for other key types.
pub fn ml_kem_ciphertext_len(key_type: KeyType) -> Option<usize> {
    match key_type {
        KeyType::MlKem512 => Some(768),
        KeyType::MlKem768 => Some(1088),
        KeyType::MlKem1024 => Some(1568),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> PivError {
    PivError::InvalidData(message.into())
}

/// Validate the encoded peer public key (ECDH) or ciphertext (ML-KEM) passed
/// to `calculate_secret` for a key of `key_type`.
pub fn check_secret_input(key_type: KeyType, data: &[u8]) -> Result<(), PivError> {
    match key_type {
        KeyType::EccP256 => p256::PublicKey::from_sec1_bytes(data)
            .map(drop)
            .map_err(|_| invalid("Invalid P-256 peer public key.")),
        KeyType::EccP384 => p384::PublicKey::from_sec1_bytes(data)
            .map(drop)
            .map_err(|_| invalid("Invalid P-384 peer public key.")),
        KeyType::X25519 if data.len() == 32 => Ok(()),
        KeyType::X25519 => Err(invalid("Invalid X25519 peer public key.")),
        KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => {
            let expected = ml_kem_ciphertext_len(key_type).unwrap_or_default();
            if data.len() == expected {
                Ok(())
            } else {
                Err(invalid(format!(
                    "Expected {expected} bytes of ML-KEM ciphertext, got {}.",
                    data.len()
                )))
            }
        }
        _ => Err(PivError::NotSupported(format!(
            "Key type {key_type} cannot calculate a shared secret."
        ))),
    }
}

/// Encode a peer public key as `calculate_secret` input for a key of `key_type`.
///
/// The peer key must use the same algorithm as the key on the YubiKey.
pub fn peer_public_key_bytes(key_type: KeyType, peer: &PublicKey) -> Result<Vec<u8>, PivError> {
    let data = match (key_type, peer) {
        (KeyType::EccP256, PublicKey::Ec(key)) if key.curve == EcCurve::P256 => key.point.clone(),
        (KeyType::EccP384, PublicKey::Ec(key)) if key.curve == EcCurve::P384 => key.point.clone(),
        (KeyType::X25519, PublicKey::X25519(key)) => key.key.clone(),
        (KeyType::EccP256 | KeyType::EccP384 | KeyType::X25519, _) => {
            return Err(invalid(
                "Peer public key algorithm must match the slot key.",
            ));
        }
        _ => {
            return Err(PivError::NotSupported(
                "Key agreement requires P-256, P-384, or X25519.".into(),
            ));
        }
    };
    check_secret_input(key_type, &data)?;
    Ok(data)
}

/// Validate a shared secret returned by `calculate_secret` for a key of `key_type`.
///
/// Rejects unexpected lengths and the all-zero X25519 output produced by
/// low-order peer points (RFC 7748, section 6.1).
pub fn check_shared_secret(key_type: KeyType, secret: &[u8]) -> Result<(), PivError> {
    let expected = match key_type {
        KeyType::EccP256 | KeyType::X25519 => 32,
        KeyType::EccP384 => 48,
        KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => ML_KEM_SHARED_SECRET_LEN,
        _ => {
            return Err(PivError::NotSupported(format!(
                "Key type {key_type} cannot calculate a shared secret."
            )));
        }
    };
    let all_zero = key_type == KeyType::X25519 && bool::from(secret.ct_eq(&[0; 32]));
    if secret.len() != expected || all_zero {
        return Err(invalid("Invalid shared secret returned by the YubiKey."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{EcPublicKey, X25519PublicKey};

    fn p256_point() -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let secret = p256::SecretKey::from_slice(&[1; 32]).unwrap();
        secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn ml_kem_ciphertexts() {
        for (key_type, len) in [
            (KeyType::MlKem512, 768),
            (KeyType::MlKem768, 1088),
            (KeyType::MlKem1024, 1568),
        ] {
            assert_eq!(ml_kem_ciphertext_len(key_type), Some(len));
            assert!(check_secret_input(key_type, &vec![0; len]).is_ok());
            assert!(check_secret_input(key_type, &vec![0; len - 1]).is_err());
            assert!(check_shared_secret(key_type, &[1; 32]).is_ok());
            assert!(check_shared_secret(key_type, &[1; 31]).is_err());
        }
        assert_eq!(ml_kem_ciphertext_len(KeyType::EccP256), None);
    }

    #[test]
    fn peer_keys() {
        let point = p256_point();
        let p256 = PublicKey::Ec(EcPublicKey {
            curve: EcCurve::P256,
            point: point.clone(),
        });
        assert_eq!(
            peer_public_key_bytes(KeyType::EccP256, &p256).unwrap(),
            point
        );
        assert!(peer_public_key_bytes(KeyType::EccP384, &p256).is_err());
        assert!(peer_public_key_bytes(KeyType::X25519, &p256).is_err());
        assert!(peer_public_key_bytes(KeyType::Rsa2048, &p256).is_err());

        let mut off_curve = point;
        *off_curve.last_mut().unwrap() ^= 1;
        let off_curve = PublicKey::Ec(EcPublicKey {
            curve: EcCurve::P256,
            point: off_curve,
        });
        assert!(peer_public_key_bytes(KeyType::EccP256, &off_curve).is_err());

        let x25519 = PublicKey::X25519(X25519PublicKey { key: vec![9; 32] });
        assert_eq!(
            peer_public_key_bytes(KeyType::X25519, &x25519).unwrap(),
            vec![9; 32]
        );
        assert!(check_secret_input(KeyType::X25519, &[9; 31]).is_err());
        assert!(check_secret_input(KeyType::Ed25519, &[9; 32]).is_err());
    }

    #[test]
    fn shared_secrets() {
        assert!(check_shared_secret(KeyType::EccP256, &[1; 32]).is_ok());
        assert!(check_shared_secret(KeyType::EccP256, &[1; 48]).is_err());
        assert!(check_shared_secret(KeyType::EccP384, &[1; 48]).is_ok());
        assert!(check_shared_secret(KeyType::X25519, &[1; 32]).is_ok());
        assert!(check_shared_secret(KeyType::X25519, &[0; 32]).is_err());
        assert!(check_shared_secret(KeyType::Rsa2048, &[1; 32]).is_err());
    }
}
