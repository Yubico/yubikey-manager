//! Host-side encodings for the raw private-key operations offered by PIV.
//!
//! The YubiKey performs raw private-key operations; hashing, signature padding
//! and decryption unpadding are done on the host.

use std::fmt;

use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use zeroize::Zeroizing;

use crate::piv::{HashAlgorithm, KeyType};

/// Error preparing or validating a host-side PIV encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingError(pub String);

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PaddingError {}

type Result<T> = std::result::Result<T, PaddingError>;

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err(PaddingError(format!($($arg)*)))
    };
}

macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            bail!($($arg)*);
        }
    };
}

/// RSA signature padding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePadding {
    /// RSASSA-PKCS1-v1_5.
    Pkcs1v15,
    /// RSASSA-PSS with a digest-length salt and MGF1 using the message hash.
    Pss,
}

/// RSA encryption padding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionPadding {
    /// RSAES-OAEP with MGF1 using the same hash and an empty label.
    Oaep,
    /// RSAES-PKCS1-v1_5.
    Pkcs1v15,
}

const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

fn digest_len(hash: HashAlgorithm) -> usize {
    match hash {
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
        HashAlgorithm::Sha512 => 64,
    }
}

fn digest(hash: HashAlgorithm, input: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(match hash {
        HashAlgorithm::Sha256 => Sha256::digest(input).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(input).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(input).to_vec(),
    })
}

fn mgf1_xor(output: &mut [u8], seed: &[u8], hash: HashAlgorithm) {
    let mut input = Zeroizing::new(Vec::with_capacity(seed.len() + 4));
    input.extend_from_slice(seed);
    input.extend_from_slice(&[0; 4]);
    for (counter, chunk) in output.chunks_mut(digest_len(hash)).enumerate() {
        input[seed.len()..].copy_from_slice(&(counter as u32).to_be_bytes());
        let mask = digest(hash, &input);
        for (byte, mask_byte) in chunk.iter_mut().zip(mask.iter()) {
            *byte ^= mask_byte;
        }
    }
}

/// Prepare the input for a PIV signature operation.
///
/// RSA and ECDSA input is hashed (SHA-256 by default) unless `prehashed` is
/// set, in which case it must be a digest of exactly the selected length.
/// RSA input is then padded, PKCS#1 v1.5 by default.
///
/// ECDSA digests longer than the curve order are truncated on the host, as
/// specified for ECDSA, since firmware differs in how it handles longer input.
/// Shorter digests are sent unchanged.
///
/// Ed25519 and ML-DSA sign the message directly and accept no hash, prehash or
/// padding options. Key agreement and KEM key types cannot sign.
pub fn prepare_signature(
    key_type: KeyType,
    input: &[u8],
    hash: Option<HashAlgorithm>,
    prehashed: bool,
    padding: Option<SignaturePadding>,
) -> Result<Vec<u8>> {
    let rsa = match key_type {
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => true,
        KeyType::EccP256 | KeyType::EccP384 => false,
        KeyType::Ed25519 | KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
            ensure!(
                hash.is_none() && !prehashed && padding.is_none(),
                "This key type signs messages directly; hash, prehashed and padding options are not supported."
            );
            return Ok(input.to_vec());
        }
        _ => bail!("Key type {key_type} cannot be used for signing."),
    };
    ensure!(
        rsa || padding.is_none(),
        "Padding is only supported for RSA."
    );
    let hash = hash.unwrap_or(HashAlgorithm::Sha256);
    let hashed = if prehashed {
        ensure!(
            input.len() == digest_len(hash),
            "Prehashed input must contain exactly {} bytes.",
            digest_len(hash)
        );
        Zeroizing::new(input.to_vec())
    } else {
        digest(hash, input)
    };
    if !rsa {
        return Ok(hashed[..hashed.len().min((key_type.bit_len() / 8) as usize)].to_vec());
    }
    let bits = key_type.bit_len() as usize;
    match padding.unwrap_or(SignaturePadding::Pkcs1v15) {
        SignaturePadding::Pkcs1v15 => {
            // RFC 8017, Appendix B.1: DigestInfo with explicit NULL parameters.
            let prefix = match hash {
                HashAlgorithm::Sha256 => DIGEST_INFO_SHA256,
                HashAlgorithm::Sha384 => DIGEST_INFO_SHA384,
                HashAlgorithm::Sha512 => DIGEST_INFO_SHA512,
            };
            let len = bits.div_ceil(8);
            ensure!(
                len >= prefix.len() + hashed.len() + 11,
                "RSA key is too small for the selected hash."
            );
            let separator = len - prefix.len() - hashed.len() - 1;
            let mut encoded = vec![0xff; len];
            encoded[..2].copy_from_slice(&[0, 1]);
            encoded[separator] = 0;
            encoded[separator + 1..separator + 1 + prefix.len()].copy_from_slice(prefix);
            encoded[separator + 1 + prefix.len()..].copy_from_slice(&hashed);
            Ok(encoded)
        }
        SignaturePadding::Pss => {
            let em_bits = bits - 1;
            let em_len = em_bits.div_ceil(8);
            let h_len = hashed.len();
            ensure!(
                em_len >= 2 * h_len + 2,
                "RSA key is too small for PSS with a digest-length salt."
            );
            let mut salt = Zeroizing::new(vec![0; h_len]);
            getrandom::fill(&mut salt)
                .map_err(|_| PaddingError("Failed to generate PSS salt".into()))?;
            let mut m_prime = Zeroizing::new(vec![0; 8]);
            m_prime.extend_from_slice(&hashed);
            m_prime.extend_from_slice(&salt);
            let h = digest(hash, &m_prime);
            let db_len = em_len - h_len - 1;
            let mut encoded = vec![0; em_len];
            encoded[db_len - h_len - 1] = 1;
            encoded[db_len - h_len..db_len].copy_from_slice(&salt);
            mgf1_xor(&mut encoded[..db_len], &h, hash);
            encoded[0] &= 0xff >> (8 * em_len - em_bits);
            encoded[db_len..em_len - 1].copy_from_slice(&h);
            encoded[em_len - 1] = 0xbc;
            Ok(encoded)
        }
    }
}

/// Remove RSA encryption padding from a raw RSA decryption result.
///
/// OAEP uses `hash` for both the label hash and MGF1, with an empty label.
/// The entire padding is validated before branching on its aggregate validity,
/// and all failures produce the same error.
///
/// This is not a constant-time decryption API: returning a variable-length
/// plaintext (and reporting success) necessarily reveals information.
pub fn unpad_rsa(
    block: &[u8],
    padding: DecryptionPadding,
    hash: HashAlgorithm,
) -> Result<Zeroizing<Vec<u8>>> {
    match padding {
        DecryptionPadding::Pkcs1v15 => {
            ensure!(block.len() >= 11, "Invalid ciphertext.");
            let decoded = Zeroizing::new(block.to_vec());
            let mut valid = decoded[0].ct_eq(&0) & decoded[1].ct_eq(&2);
            let mut searching = Choice::from(1);
            let mut separator = 0u64;
            for (index, byte) in decoded.iter().enumerate().skip(2) {
                let is_zero = byte.ct_eq(&0);
                separator =
                    u64::conditional_select(&separator, &(index as u64), searching & is_zero);
                searching &= !is_zero;
            }
            valid &= !searching & !separator.ct_lt(&10);
            ensure!(bool::from(valid), "Invalid ciphertext.");
            Ok(Zeroizing::new(decoded[separator as usize + 1..].to_vec()))
        }
        DecryptionPadding::Oaep => {
            let h_len = digest_len(hash);
            ensure!(block.len() >= 2 * h_len + 2, "Invalid ciphertext.");
            let mut decoded = Zeroizing::new(block.to_vec());
            let mut valid = decoded[0].ct_eq(&0);
            let (seed, db) = decoded[1..].split_at_mut(h_len);
            mgf1_xor(seed, db, hash);
            mgf1_xor(db, seed, hash);
            let l_hash = digest(hash, b"");
            valid &= db[..h_len].ct_eq(l_hash.as_slice());
            let mut searching = Choice::from(1);
            let mut separator = 0u64;
            for (index, byte) in db.iter().enumerate().skip(h_len) {
                let is_zero = byte.ct_eq(&0);
                let is_one = byte.ct_eq(&1);
                valid &= !(searching & !(is_zero | is_one));
                separator =
                    u64::conditional_select(&separator, &(index as u64), searching & is_one);
                searching &= !is_one;
            }
            valid &= !searching;
            ensure!(bool::from(valid), "Invalid ciphertext.");
            Ok(Zeroizing::new(db[separator as usize + 1..].to_vec()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::rand_core::OsRng;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use rsa::{BigUint, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
    use std::sync::OnceLock;

    const HASHES: [HashAlgorithm; 3] = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];
    const RSA_TYPES: [KeyType; 4] = [
        KeyType::Rsa1024,
        KeyType::Rsa2048,
        KeyType::Rsa3072,
        KeyType::Rsa4096,
    ];

    fn private_key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048).unwrap())
    }

    // A real test key's raw private operation, deliberately without unpadding.
    fn raw_private(input: &[u8]) -> Vec<u8> {
        let key = private_key();
        let number = BigUint::from_bytes_be(input);
        assert!(&number < key.n());
        let result = number.modpow(key.d(), key.n()).to_bytes_be();
        let mut block = vec![0; key.size()];
        let start = block.len() - result.len();
        block[start..].copy_from_slice(&result);
        block
    }

    #[test]
    fn rsa_signatures_verify_independently() {
        let public = RsaPublicKey::from(private_key());
        let message = b"PIV signature encoding";
        for hash in HASHES {
            let hashed = digest(hash, message);
            for padding in [SignaturePadding::Pkcs1v15, SignaturePadding::Pss] {
                for prehashed in [false, true] {
                    let input = if prehashed {
                        hashed.as_slice()
                    } else {
                        message
                    };
                    let encoded = prepare_signature(
                        KeyType::Rsa2048,
                        input,
                        Some(hash),
                        prehashed,
                        Some(padding),
                    )
                    .unwrap();
                    let signature = raw_private(&encoded);
                    match padding {
                        SignaturePadding::Pkcs1v15 => {
                            let prefix = match hash {
                                HashAlgorithm::Sha256 => "3031300d060960864801650304020105000420",
                                HashAlgorithm::Sha384 => "3041300d060960864801650304020205000430",
                                HashAlgorithm::Sha512 => "3051300d060960864801650304020305000440",
                            };
                            let mut digest_info: Vec<u8> = (0..prefix.len())
                                .step_by(2)
                                .map(|i| u8::from_str_radix(&prefix[i..i + 2], 16).unwrap())
                                .collect();
                            digest_info.extend_from_slice(&hashed);
                            public
                                .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, &signature)
                                .unwrap();
                        }
                        SignaturePadding::Pss => match hash {
                            HashAlgorithm::Sha256 => {
                                public.verify(Pss::new_with_salt::<Sha256>(32), &hashed, &signature)
                            }
                            HashAlgorithm::Sha384 => {
                                public.verify(Pss::new_with_salt::<Sha384>(48), &hashed, &signature)
                            }
                            HashAlgorithm::Sha512 => {
                                public.verify(Pss::new_with_salt::<Sha512>(64), &hashed, &signature)
                            }
                        }
                        .unwrap(),
                    }
                }
            }
        }
    }

    #[test]
    fn rsa_key_sizes_and_defaults() {
        for key_type in RSA_TYPES {
            for hash in HASHES {
                let default =
                    prepare_signature(key_type, b"message", Some(hash), false, None).unwrap();
                let explicit = prepare_signature(
                    key_type,
                    b"message",
                    Some(hash),
                    false,
                    Some(SignaturePadding::Pkcs1v15),
                )
                .unwrap();
                assert_eq!(default, explicit);
                assert_eq!(default.len(), key_type.bit_len() as usize / 8);
                let pss = prepare_signature(
                    key_type,
                    b"message",
                    Some(hash),
                    false,
                    Some(SignaturePadding::Pss),
                );
                if key_type == KeyType::Rsa1024 && matches!(hash, HashAlgorithm::Sha512) {
                    assert!(pss.is_err());
                } else {
                    let encoded = pss.unwrap();
                    assert_eq!(encoded.len(), default.len());
                    assert_eq!(encoded[0] & 0x80, 0);
                    assert_eq!(encoded.last(), Some(&0xbc));
                }
            }
        }
        assert_eq!(
            prepare_signature(KeyType::Rsa2048, b"message", None, false, None).unwrap(),
            prepare_signature(
                KeyType::Rsa2048,
                b"message",
                Some(HashAlgorithm::Sha256),
                false,
                None
            )
            .unwrap()
        );
        assert_ne!(
            prepare_signature(
                KeyType::Rsa2048,
                b"message",
                None,
                false,
                Some(SignaturePadding::Pss)
            )
            .unwrap(),
            prepare_signature(
                KeyType::Rsa2048,
                b"message",
                None,
                false,
                Some(SignaturePadding::Pss)
            )
            .unwrap()
        );
    }

    #[test]
    fn ec_hashes_truncate_and_prehashed_lengths_are_exact() {
        for key_type in [KeyType::EccP256, KeyType::EccP384] {
            for hash in HASHES {
                let hashed = digest(hash, b"message");
                let expected = &hashed[..hashed.len().min(key_type.bit_len() as usize / 8)];
                for prehashed in [false, true] {
                    let input = if prehashed {
                        hashed.as_slice()
                    } else {
                        b"message"
                    };
                    assert_eq!(
                        prepare_signature(key_type, input, Some(hash), prehashed, None).unwrap(),
                        expected
                    );
                }
            }
        }
        for key_type in RSA_TYPES
            .into_iter()
            .chain([KeyType::EccP256, KeyType::EccP384])
        {
            for hash in HASHES {
                for len in [0, digest_len(hash) - 1, digest_len(hash) + 1] {
                    assert!(
                        prepare_signature(key_type, &vec![0; len], Some(hash), true, None).is_err()
                    );
                }
            }
        }
        assert!(prepare_signature(KeyType::EccP256, &[0; 32], None, true, None).is_ok());
    }

    #[test]
    fn direct_message_keys_and_invalid_flags() {
        for key_type in [
            KeyType::Ed25519,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
            KeyType::MlDsa87,
        ] {
            for message in [b"".as_slice(), b"message"] {
                assert_eq!(
                    prepare_signature(key_type, message, None, false, None).unwrap(),
                    message
                );
            }
            assert!(
                prepare_signature(
                    key_type,
                    b"message",
                    Some(HashAlgorithm::Sha256),
                    false,
                    None
                )
                .is_err()
            );
            assert!(prepare_signature(key_type, &[0; 32], None, true, None).is_err());
        }
        for key_type in [
            KeyType::EccP256,
            KeyType::EccP384,
            KeyType::Ed25519,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
            KeyType::MlDsa87,
        ] {
            for padding in [SignaturePadding::Pkcs1v15, SignaturePadding::Pss] {
                assert!(
                    prepare_signature(key_type, b"message", None, false, Some(padding)).is_err()
                );
            }
        }
        for key_type in [
            KeyType::X25519,
            KeyType::MlKem512,
            KeyType::MlKem768,
            KeyType::MlKem1024,
        ] {
            assert!(prepare_signature(key_type, b"message", None, false, None).is_err());
        }
    }

    fn encrypt_oaep(public: &RsaPublicKey, message: &[u8], hash: HashAlgorithm) -> Vec<u8> {
        match hash {
            HashAlgorithm::Sha256 => public.encrypt(&mut OsRng, Oaep::new::<Sha256>(), message),
            HashAlgorithm::Sha384 => public.encrypt(&mut OsRng, Oaep::new::<Sha384>(), message),
            HashAlgorithm::Sha512 => public.encrypt(&mut OsRng, Oaep::new::<Sha512>(), message),
        }
        .unwrap()
    }

    #[test]
    fn independent_encryptions_unpad() {
        let public = RsaPublicKey::from(private_key());
        for hash in HASHES {
            for len in [0, 1, public.size() - 2 * digest_len(hash) - 2] {
                let message = vec![0x42; len];
                let ciphertext = encrypt_oaep(&public, &message, hash);
                let block = raw_private(&ciphertext);
                assert_eq!(
                    unpad_rsa(&block, DecryptionPadding::Oaep, hash)
                        .unwrap()
                        .as_slice(),
                    message
                );
            }
            for len in [0, 1, public.size() - 11] {
                let message = vec![0; len];
                let ciphertext = public
                    .encrypt(&mut OsRng, Pkcs1v15Encrypt, &message)
                    .unwrap();
                let block = raw_private(&ciphertext);
                assert_eq!(
                    unpad_rsa(&block, DecryptionPadding::Pkcs1v15, hash)
                        .unwrap()
                        .as_slice(),
                    message
                );
            }
        }
    }

    fn assert_invalid(block: &[u8], padding: DecryptionPadding, hash: HashAlgorithm) {
        assert_eq!(
            unpad_rsa(block, padding, hash).unwrap_err().to_string(),
            "Invalid ciphertext."
        );
    }

    #[test]
    fn pkcs1v15_malformed_padding_and_lengths() {
        let hash = HashAlgorithm::Sha256;
        for len in 0..11 {
            assert_invalid(&vec![0; len], DecryptionPadding::Pkcs1v15, hash);
        }
        let mut valid = vec![0, 2];
        valid.extend_from_slice(&[0x42; 8]);
        valid.push(0);
        assert!(
            unpad_rsa(&valid, DecryptionPadding::Pkcs1v15, hash)
                .unwrap()
                .is_empty()
        );
        for index in [0, 1, 10] {
            let mut invalid = valid.clone();
            invalid[index] ^= 1;
            assert_invalid(&invalid, DecryptionPadding::Pkcs1v15, hash);
        }
        for separator in 2..10 {
            let mut invalid = valid.clone();
            invalid[separator] = 0;
            assert_invalid(&invalid, DecryptionPadding::Pkcs1v15, hash);
        }
        assert_invalid(&[0xff; 128], DecryptionPadding::Pkcs1v15, hash);
    }

    // Construct malformed *decoded* OAEP fields, then mask them so validation
    // exercises each condition rather than failing on an unrelated label hash.
    fn mask_oaep(db: &[u8], hash: HashAlgorithm) -> Vec<u8> {
        let h_len = digest_len(hash);
        let mut block = vec![0; 1 + h_len + db.len()];
        let (seed, masked_db) = block[1..].split_at_mut(h_len);
        seed.fill(0x42);
        masked_db.copy_from_slice(db);
        mgf1_xor(masked_db, seed, hash);
        mgf1_xor(seed, masked_db, hash);
        block
    }

    #[test]
    fn oaep_malformed_padding_lengths_labels_and_hashes() {
        let public = RsaPublicKey::from(private_key());
        for hash in HASHES {
            let h_len = digest_len(hash);
            for len in [0, 1, h_len, 2 * h_len + 1] {
                assert_invalid(&vec![0; len], DecryptionPadding::Oaep, hash);
            }
            let mut db = digest(hash, b"").to_vec();
            db.extend_from_slice(&[0, 0, 1, 0x42, 0, 1]);
            let valid = mask_oaep(&db, hash);
            assert_eq!(
                unpad_rsa(&valid, DecryptionPadding::Oaep, hash)
                    .unwrap()
                    .as_slice(),
                &[0x42, 0, 1]
            );
            let mut bad_header = valid.clone();
            bad_header[0] = 1;
            assert_invalid(&bad_header, DecryptionPadding::Oaep, hash);
            for index in [0, h_len, h_len + 1, h_len + 2] {
                let mut invalid_db = db.clone();
                invalid_db[index] ^= 0x42;
                assert_invalid(&mask_oaep(&invalid_db, hash), DecryptionPadding::Oaep, hash);
            }
            let mut no_separator = digest(hash, b"").to_vec();
            no_separator.extend_from_slice(&[0; 8]);
            assert_invalid(
                &mask_oaep(&no_separator, hash),
                DecryptionPadding::Oaep,
                hash,
            );
            let mut wrong_label = digest(hash, b"nonempty label").to_vec();
            wrong_label.extend_from_slice(&[0, 1, 0x42]);
            assert_invalid(
                &mask_oaep(&wrong_label, hash),
                DecryptionPadding::Oaep,
                hash,
            );
            let encrypted = encrypt_oaep(&public, b"message", hash);
            let block = raw_private(&encrypted);
            for other_hash in HASHES {
                if digest_len(other_hash) != h_len {
                    assert_invalid(&block, DecryptionPadding::Oaep, other_hash);
                }
            }
        }
    }
}
