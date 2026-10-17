//! Host-side hashing and RSA padding for private-key operations on a YubiKey.
//!
//! PIV performs raw private-key operations, so hashing, signature padding and
//! decryption unpadding are done on the host. OpenPGP pads on the card but
//! still needs the DigestInfo encoding for RSA signatures.

use std::fmt;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use zeroize::Zeroizing;

use crate::piv::{HashAlgorithm, KeyType};

/// Error preparing or validating a host-side encoding.
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

/// Hash algorithm for host-side hashing, DigestInfo, PSS, OAEP and MGF1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl Hash {
    /// Look up a hash by its name in the Python `cryptography` package.
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(match name {
            "sha1" => Self::Sha1,
            "sha224" => Self::Sha224,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            "sha512-224" => Self::Sha512_224,
            "sha512-256" => Self::Sha512_256,
            "sha3-224" => Self::Sha3_224,
            "sha3-256" => Self::Sha3_256,
            "sha3-384" => Self::Sha3_384,
            "sha3-512" => Self::Sha3_512,
            _ => bail!("Unsupported hash algorithm: {name}"),
        })
    }

    /// Digest length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha512_256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }

    /// Hash `data`.
    pub fn digest(self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        fn run<D: sha2::Digest>(data: &[u8]) -> Vec<u8> {
            D::digest(data).to_vec()
        }
        Zeroizing::new(match self {
            Self::Sha1 => run::<sha1::Sha1>(data),
            Self::Sha224 => run::<sha2::Sha224>(data),
            Self::Sha256 => run::<sha2::Sha256>(data),
            Self::Sha384 => run::<sha2::Sha384>(data),
            Self::Sha512 => run::<sha2::Sha512>(data),
            Self::Sha512_224 => run::<sha2::Sha512_224>(data),
            Self::Sha512_256 => run::<sha2::Sha512_256>(data),
            Self::Sha3_224 => run::<sha3::Sha3_224>(data),
            Self::Sha3_256 => run::<sha3::Sha3_256>(data),
            Self::Sha3_384 => run::<sha3::Sha3_384>(data),
            Self::Sha3_512 => run::<sha3::Sha3_512>(data),
        })
    }

    /// DER-encoded DigestInfo with explicit NULL parameters (RFC 8017, section 9.2).
    pub fn digest_info(self, digest: &[u8]) -> Result<Vec<u8>> {
        let h_len = self.output_len();
        ensure!(
            digest.len() == h_len,
            "Digest must contain exactly {h_len} bytes."
        );
        // OIDs 2.16.840.1.101.3.4.2.<arc> (NIST hash algorithms).
        let nist_arc = match self {
            Self::Sha1 => None,
            Self::Sha256 => Some(1),
            Self::Sha384 => Some(2),
            Self::Sha512 => Some(3),
            Self::Sha224 => Some(4),
            Self::Sha512_224 => Some(5),
            Self::Sha512_256 => Some(6),
            Self::Sha3_224 => Some(7),
            Self::Sha3_256 => Some(8),
            Self::Sha3_384 => Some(9),
            Self::Sha3_512 => Some(10),
        };
        let mut encoded = match nist_arc {
            None => vec![
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
                0x14,
            ],
            Some(arc) => vec![
                0x30,
                17 + h_len as u8,
                0x30,
                0x0D,
                0x06,
                0x09,
                0x60,
                0x86,
                0x48,
                0x01,
                0x65,
                0x03,
                0x04,
                0x02,
                arc,
                0x05,
                0x00,
                0x04,
                h_len as u8,
            ],
        };
        encoded.extend_from_slice(digest);
        Ok(encoded)
    }
}

impl From<HashAlgorithm> for Hash {
    fn from(hash: HashAlgorithm) -> Self {
        match hash {
            HashAlgorithm::Sha256 => Self::Sha256,
            HashAlgorithm::Sha384 => Self::Sha384,
            HashAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

fn mgf1_xor(output: &mut [u8], seed: &[u8], hash: Hash) {
    let mut input = Zeroizing::new(Vec::with_capacity(seed.len() + 4));
    input.extend_from_slice(seed);
    input.extend_from_slice(&[0; 4]);
    for (counter, chunk) in output.chunks_mut(hash.output_len()).enumerate() {
        input[seed.len()..].copy_from_slice(&(counter as u32).to_be_bytes());
        let mask = hash.digest(&input);
        for (byte, mask_byte) in chunk.iter_mut().zip(mask.iter()) {
            *byte ^= mask_byte;
        }
    }
}

/// EMSA-PKCS1-v1_5 encoding of `digest` for a `bits`-bit RSA modulus.
pub fn pkcs1v15_sign_pad(bits: usize, hash: Hash, digest: &[u8]) -> Result<Vec<u8>> {
    let digest_info = hash.digest_info(digest)?;
    let len = bits.div_ceil(8);
    ensure!(
        len >= digest_info.len() + 11,
        "RSA key is too small for the selected hash."
    );
    let mut encoded = vec![0xff; len];
    encoded[..2].copy_from_slice(&[0, 1]);
    encoded[len - digest_info.len() - 1] = 0;
    encoded[len - digest_info.len()..].copy_from_slice(&digest_info);
    Ok(encoded)
}

/// EMSA-PSS encoding of `digest` for a `bits`-bit RSA modulus, padded to the
/// modulus length.
///
/// A `salt_len` of `None` selects the maximum salt length.
pub fn pss_sign_pad(
    bits: usize,
    hash: Hash,
    digest: &[u8],
    salt_len: Option<usize>,
    mgf_hash: Hash,
) -> Result<Vec<u8>> {
    let h_len = hash.output_len();
    ensure!(
        digest.len() == h_len,
        "Digest must contain exactly {h_len} bytes."
    );
    ensure!(bits >= 2, "Invalid RSA key size.");
    let em_bits = bits - 1;
    let em_len = em_bits.div_ceil(8);
    let too_small = "RSA key is too small for the selected PSS parameters.";
    ensure!(em_len >= h_len + 2, "{too_small}");
    let salt_len = salt_len.unwrap_or(em_len - h_len - 2);
    ensure!(em_len >= h_len + salt_len + 2, "{too_small}");
    let mut salt = Zeroizing::new(vec![0; salt_len]);
    getrandom::fill(&mut salt).map_err(|_| PaddingError("Failed to generate PSS salt".into()))?;
    let mut m_prime = Zeroizing::new(vec![0; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);
    let h = hash.digest(&m_prime);
    let db_len = em_len - h_len - 1;
    let mut encoded = vec![0; em_len];
    encoded[db_len - salt_len - 1] = 1;
    encoded[db_len - salt_len..db_len].copy_from_slice(&salt);
    mgf1_xor(&mut encoded[..db_len], &h, mgf_hash);
    encoded[0] &= 0xff >> (8 * em_len - em_bits);
    encoded[db_len..em_len - 1].copy_from_slice(&h);
    encoded[em_len - 1] = 0xbc;
    if em_len < bits.div_ceil(8) {
        encoded.insert(0, 0);
    }
    Ok(encoded)
}

/// Remove RSAES-PKCS1-v1_5 padding from a raw RSA decryption result.
///
/// The entire padding is validated before branching on its aggregate validity,
/// and all failures produce the same error. This is not a constant-time
/// decryption API: returning a variable-length plaintext (and reporting
/// success) necessarily reveals information.
pub fn pkcs1v15_decrypt_unpad(block: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(block.len() >= 11, "Invalid ciphertext.");
    let decoded = Zeroizing::new(block.to_vec());
    let mut valid = decoded[0].ct_eq(&0) & decoded[1].ct_eq(&2);
    let mut searching = Choice::from(1);
    let mut separator = 0u64;
    for (index, byte) in decoded.iter().enumerate().skip(2) {
        let is_zero = byte.ct_eq(&0);
        separator = u64::conditional_select(&separator, &(index as u64), searching & is_zero);
        searching &= !is_zero;
    }
    valid &= !searching & !separator.ct_lt(&10);
    ensure!(bool::from(valid), "Invalid ciphertext.");
    Ok(Zeroizing::new(decoded[separator as usize + 1..].to_vec()))
}

/// Remove RSAES-OAEP padding from a raw RSA decryption result.
///
/// See [`pkcs1v15_decrypt_unpad`] for the error-handling properties.
pub fn oaep_decrypt_unpad(
    block: &[u8],
    hash: Hash,
    mgf_hash: Hash,
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let h_len = hash.output_len();
    ensure!(block.len() >= 2 * h_len + 2, "Invalid ciphertext.");
    let mut decoded = Zeroizing::new(block.to_vec());
    let mut valid = decoded[0].ct_eq(&0);
    let (seed, db) = decoded[1..].split_at_mut(h_len);
    mgf1_xor(seed, db, mgf_hash);
    mgf1_xor(db, seed, mgf_hash);
    let l_hash = hash.digest(label);
    valid &= db[..h_len].ct_eq(l_hash.as_slice());
    let mut searching = Choice::from(1);
    let mut separator = 0u64;
    for (index, byte) in db.iter().enumerate().skip(h_len) {
        let is_zero = byte.ct_eq(&0);
        let is_one = byte.ct_eq(&1);
        valid &= !(searching & !(is_zero | is_one));
        separator = u64::conditional_select(&separator, &(index as u64), searching & is_one);
        searching &= !is_one;
    }
    valid &= !searching;
    ensure!(bool::from(valid), "Invalid ciphertext.");
    Ok(Zeroizing::new(db[separator as usize + 1..].to_vec()))
}

/// RSA signature padding scheme for PIV signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePadding {
    /// RSASSA-PKCS1-v1_5.
    Pkcs1v15,
    /// RSASSA-PSS with a digest-length salt and MGF1 using the message hash.
    Pss,
}

/// RSA encryption padding scheme for PIV decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionPadding {
    /// RSAES-OAEP with MGF1 using the same hash and an empty label.
    Oaep,
    /// RSAES-PKCS1-v1_5.
    Pkcs1v15,
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
    let hash = Hash::from(hash.unwrap_or(HashAlgorithm::Sha256));
    let hashed = if prehashed {
        ensure!(
            input.len() == hash.output_len(),
            "Prehashed input must contain exactly {} bytes.",
            hash.output_len()
        );
        Zeroizing::new(input.to_vec())
    } else {
        hash.digest(input)
    };
    let bits = key_type.bit_len() as usize;
    if !rsa {
        return Ok(hashed[..hashed.len().min(bits / 8)].to_vec());
    }
    match padding.unwrap_or(SignaturePadding::Pkcs1v15) {
        SignaturePadding::Pkcs1v15 => pkcs1v15_sign_pad(bits, hash, &hashed),
        SignaturePadding::Pss => pss_sign_pad(bits, hash, &hashed, Some(hash.output_len()), hash),
    }
}

/// Remove RSA encryption padding from a raw PIV RSA decryption result.
///
/// OAEP uses `hash` for both the label hash and MGF1, with an empty label.
pub fn unpad_rsa(
    block: &[u8],
    padding: DecryptionPadding,
    hash: HashAlgorithm,
) -> Result<Zeroizing<Vec<u8>>> {
    match padding {
        DecryptionPadding::Pkcs1v15 => pkcs1v15_decrypt_unpad(block),
        DecryptionPadding::Oaep => oaep_decrypt_unpad(block, hash.into(), hash.into(), b""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::rand_core::OsRng;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use rsa::{BigUint, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
    use sha2::{Sha256, Sha384, Sha512};
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
            let hashed = Hash::from(hash).digest(message);
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
                let hashed = Hash::from(hash).digest(b"message");
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
                for len in [
                    0,
                    Hash::from(hash).output_len() - 1,
                    Hash::from(hash).output_len() + 1,
                ] {
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
            for len in [0, 1, public.size() - 2 * Hash::from(hash).output_len() - 2] {
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
        let h_len = Hash::from(hash).output_len();
        let mut block = vec![0; 1 + h_len + db.len()];
        let (seed, masked_db) = block[1..].split_at_mut(h_len);
        seed.fill(0x42);
        masked_db.copy_from_slice(db);
        mgf1_xor(masked_db, seed, hash.into());
        mgf1_xor(seed, masked_db, hash.into());
        block
    }

    #[test]
    fn oaep_malformed_padding_lengths_labels_and_hashes() {
        let public = RsaPublicKey::from(private_key());
        for hash in HASHES {
            let h_len = Hash::from(hash).output_len();
            for len in [0, 1, h_len, 2 * h_len + 1] {
                assert_invalid(&vec![0; len], DecryptionPadding::Oaep, hash);
            }
            let mut db = Hash::from(hash).digest(b"").to_vec();
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
            let mut no_separator = Hash::from(hash).digest(b"").to_vec();
            no_separator.extend_from_slice(&[0; 8]);
            assert_invalid(
                &mask_oaep(&no_separator, hash),
                DecryptionPadding::Oaep,
                hash,
            );
            let mut wrong_label = Hash::from(hash).digest(b"nonempty label").to_vec();
            wrong_label.extend_from_slice(&[0, 1, 0x42]);
            assert_invalid(
                &mask_oaep(&wrong_label, hash),
                DecryptionPadding::Oaep,
                hash,
            );
            let encrypted = encrypt_oaep(&public, b"message", hash);
            let block = raw_private(&encrypted);
            for other_hash in HASHES {
                if Hash::from(other_hash).output_len() != h_len {
                    assert_invalid(&block, DecryptionPadding::Oaep, other_hash);
                }
            }
        }
    }

    const ALL_HASHES: [(Hash, &str, &str); 11] = [
        (Hash::Sha1, "sha1", "3021300906052b0e03021a05000414"),
        (
            Hash::Sha224,
            "sha224",
            "302d300d06096086480165030402040500041c",
        ),
        (
            Hash::Sha256,
            "sha256",
            "3031300d060960864801650304020105000420",
        ),
        (
            Hash::Sha384,
            "sha384",
            "3041300d060960864801650304020205000430",
        ),
        (
            Hash::Sha512,
            "sha512",
            "3051300d060960864801650304020305000440",
        ),
        (
            Hash::Sha512_224,
            "sha512-224",
            "302d300d06096086480165030402050500041c",
        ),
        (
            Hash::Sha512_256,
            "sha512-256",
            "3031300d060960864801650304020605000420",
        ),
        (
            Hash::Sha3_224,
            "sha3-224",
            "302d300d06096086480165030402070500041c",
        ),
        (
            Hash::Sha3_256,
            "sha3-256",
            "3031300d060960864801650304020805000420",
        ),
        (
            Hash::Sha3_384,
            "sha3-384",
            "3041300d060960864801650304020905000430",
        ),
        (
            Hash::Sha3_512,
            "sha3-512",
            "3051300d060960864801650304020a05000440",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hash_names_lengths_and_digest_infos() {
        for (hash, name, prefix) in ALL_HASHES {
            assert_eq!(Hash::from_name(name).unwrap(), hash);
            let digest = hash.digest(b"abc");
            assert_eq!(digest.len(), hash.output_len());
            let info = hash.digest_info(&digest).unwrap();
            assert_eq!(hex(&info[..info.len() - digest.len()]), prefix);
            assert!(hash.digest_info(&digest[1..]).is_err());
        }
        // FIPS 202 test vector.
        assert_eq!(
            hex(&Hash::Sha3_256.digest(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert!(Hash::from_name("md5").is_err());
    }

    #[test]
    fn pss_salt_lengths_verify_independently() {
        let public = RsaPublicKey::from(private_key());
        let hashed = Hash::Sha256.digest(b"message");
        let max_salt = public.size() - 32 - 2;
        for (salt_len, expected) in [(None, max_salt), (Some(0), 0), (Some(20), 20)] {
            let encoded =
                pss_sign_pad(2048, Hash::Sha256, &hashed, salt_len, Hash::Sha256).unwrap();
            let signature = raw_private(&encoded);
            public
                .verify(Pss::new_with_salt::<Sha256>(expected), &hashed, &signature)
                .unwrap();
        }
        assert!(
            pss_sign_pad(
                2048,
                Hash::Sha256,
                &hashed,
                Some(max_salt + 1),
                Hash::Sha256
            )
            .is_err()
        );
        assert!(pss_sign_pad(2048, Hash::Sha256, &hashed[1..], None, Hash::Sha256).is_err());
    }

    #[test]
    fn oaep_mgf_hash_and_label_unpad() {
        let public = RsaPublicKey::from(private_key());
        let padding = Oaep::new_with_mgf_hash_and_label::<Sha256, sha1::Sha1, _>("label");
        let ciphertext = public.encrypt(&mut OsRng, padding, b"secret").unwrap();
        let block = raw_private(&ciphertext);
        assert_eq!(
            oaep_decrypt_unpad(&block, Hash::Sha256, Hash::Sha1, b"label")
                .unwrap()
                .as_slice(),
            b"secret"
        );
        assert!(oaep_decrypt_unpad(&block, Hash::Sha256, Hash::Sha256, b"label").is_err());
        assert!(oaep_decrypt_unpad(&block, Hash::Sha256, Hash::Sha1, b"").is_err());
    }
}
