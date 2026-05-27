use elliptic_curve::NonZeroScalar;
/// ARKG-P256 key derivation for previewSign extension tests.
///
/// WARNING: This code is for testing purposes only and is not intended to be a
/// secure or complete implementation of ARKG.
///
/// Implements the ARKG (Asynchronous Remote Key Generation) algorithm for
/// P-256 following the spec at:
/// https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-10.html#ARKG-P256
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, PublicKey, Scalar, SecretKey};
use sha2::Sha256;
use yubikit::cbor::{self, Value};

/// Parse an ARKG master public key from CBOR (COSE_Key format).
///
/// The master key has:
/// - key -1: pk_bl (nested COSE_Key, P-256)
/// - key -2: pk_kem (nested COSE_Key, P-256)
/// - key -3: algorithm for derived keys (integer)
pub struct ArkgMasterKey {
    pub pk_bl: PublicKey,
    pub pk_kem: PublicKey,
    #[allow(dead_code)]
    pub derived_alg: i64,
}

impl ArkgMasterKey {
    /// Parse from raw CBOR bytes (the publicKey output from previewSign).
    pub fn from_cbor(data: &[u8]) -> Self {
        let value = cbor::decode(data).expect("master key CBOR");
        Self::from_value(&value)
    }

    fn from_value(value: &Value) -> Self {
        let pk_bl_val = value
            .map_get_int(-1)
            .expect("master key: missing pk_bl at key -1");
        let pk_bl = cose_key_to_p256(pk_bl_val);

        let pk_kem_val = value
            .map_get_int(-2)
            .expect("master key: missing pk_kem at key -2");
        let pk_kem = cose_key_to_p256(pk_kem_val);

        let derived_alg = value
            .map_get_int(-3)
            .and_then(|v| v.as_int())
            .expect("master key: missing derived_alg at key -3");

        Self {
            pk_bl,
            pk_kem,
            derived_alg,
        }
    }

    /// Construct from raw uncompressed P-256 public keys (65 bytes each, 0x04 prefix).
    pub fn from_raw_keys(pk_bl_bytes: &[u8], pk_kem_bytes: &[u8]) -> Self {
        let pk_bl = public_key_from_uncompressed(pk_bl_bytes);
        let pk_kem = public_key_from_uncompressed(pk_kem_bytes);
        Self {
            pk_bl,
            pk_kem,
            derived_alg: -7, // ES256
        }
    }
}

/// Parse a COSE_Key (EC2, P-256) into a p256::PublicKey.
fn cose_key_to_p256(value: &Value) -> PublicKey {
    let x = value
        .map_get_int(-2)
        .and_then(|v| v.as_bytes())
        .expect("COSE key: missing x at key -2");
    let y = value
        .map_get_int(-3)
        .and_then(|v| v.as_bytes())
        .expect("COSE key: missing y at key -3");

    assert_eq!(x.len(), 32, "P-256 x-coordinate must be 32 bytes");
    assert_eq!(y.len(), 32, "P-256 y-coordinate must be 32 bytes");

    let ep = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let affine = AffinePoint::from_encoded_point(&ep).unwrap();
    PublicKey::from_affine(affine).unwrap()
}

/// Parse an uncompressed point (0x04 || x || y) into a PublicKey.
fn public_key_from_uncompressed(bytes: &[u8]) -> PublicKey {
    assert_eq!(bytes.len(), 65, "expected 65-byte uncompressed point");
    assert_eq!(bytes[0], 0x04, "expected uncompressed point prefix");
    let ep = EncodedPoint::from_bytes(bytes).expect("valid encoded point");
    let affine = AffinePoint::from_encoded_point(&ep).unwrap();
    PublicKey::from_affine(affine).unwrap()
}

/// Derive a child public key and COSE_Sign_Args using ARKG-P256.
///
/// Returns (derived_public_key, cose_sign_args_cbor).
pub fn derive_public_key(master: &ArkgMasterKey, ikm: &[u8], ctx: &[u8]) -> (PublicKey, Vec<u8>) {
    assert!(ctx.len() <= 64, "ctx must be at most 64 bytes");

    // ctx' = I2OSP(LEN(ctx), 1) || ctx
    let mut ctx_prime = vec![ctx.len() as u8];
    ctx_prime.extend_from_slice(ctx);

    // ctx_bl = "ARKG-Derive-Key-BL." || ctx'
    let mut ctx_bl = b"ARKG-Derive-Key-BL.".to_vec();
    ctx_bl.extend_from_slice(&ctx_prime);

    // ctx_kem = "ARKG-Derive-Key-KEM." || ctx'
    let mut ctx_kem = b"ARKG-Derive-Key-KEM.".to_vec();
    ctx_kem.extend_from_slice(&ctx_prime);

    // (ikm_tau, c) = KEM-Encaps(pk_kem, ikm, ctx_kem)
    let (ikm_tau, c) = kem_encaps(&master.pk_kem, ikm, &ctx_kem);

    // tau = BL-PRF(ikm_tau, ctx_bl)
    let tau = bl_prf(&ikm_tau, &ctx_bl);

    // pk' = BL-Blind-Public-Key(pk_bl, tau) = pk_bl + tau*G
    let tau_point = ProjectivePoint::GENERATOR * tau;
    let pk_bl_point: ProjectivePoint = master.pk_bl.as_affine().into();
    let pk_derived_point = pk_bl_point + tau_point;
    let pk_derived = PublicKey::from_affine(pk_derived_point.to_affine()).unwrap();

    // kh = c
    let kh = c;

    // Build COSE_Sign_Args: { 3: alg, -1: kh, -2: ctx }
    let args = Value::Map(vec![
        (Value::Int(3), Value::Int(-65539)), // ESP256_SPLIT_ARKG_PLACEHOLDER
        (Value::Int(-1), Value::Bytes(kh)),
        (Value::Int(-2), Value::Bytes(ctx.to_vec())),
    ]);
    let args_cbor = cbor::encode(&args);

    (pk_derived, args_cbor)
}

/// KEM-Encaps following ARKG-KEM-HMAC (Section 3.3 of the ARKG draft).
fn kem_encaps(pk_kem: &PublicKey, ikm: &[u8], ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // ctx_sub = "ARKG-KEM-HMAC." || DST_ext || ctx
    // where DST_ext = "ARKG-ECDH.ARKG-P256"
    let dst_ext = b"ARKG-ECDH.ARKG-P256";
    let mut ctx_sub = b"ARKG-KEM-HMAC.".to_vec();
    ctx_sub.extend_from_slice(dst_ext);
    ctx_sub.extend_from_slice(ctx);

    // (k', c') = Sub-Kem-Encaps(pk_kem, ikm, ctx_sub)
    let (k_prime, c_prime) = sub_kem_encaps(pk_kem, ikm, &ctx_sub);

    // prk = HKDF-Extract(salt=None, IKM=k')
    // mk = HKDF-Expand(PRK=prk, info="ARKG-KEM-HMAC-mac." || DST_ext || ctx, L=32)
    let mut mac_info = b"ARKG-KEM-HMAC-mac.".to_vec();
    mac_info.extend_from_slice(dst_ext);
    mac_info.extend_from_slice(ctx);

    let hk = Hkdf::<Sha256>::new(None, &k_prime);
    let mut mk = [0u8; 32];
    hk.expand(&mac_info, &mut mk).expect("HKDF expand for mk");

    // t = HMAC-SHA-256-128(K=mk, text=c')  (truncated to 16 bytes)
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&mk).unwrap();
    hmac.update(&c_prime);
    let t_full = hmac.finalize().into_bytes();
    let t = &t_full[..16];

    // k = HKDF-Expand(PRK=prk, info="ARKG-KEM-HMAC-shared." || DST_ext || ctx, L=len(k'))
    let mut shared_info = b"ARKG-KEM-HMAC-shared.".to_vec();
    shared_info.extend_from_slice(dst_ext);
    shared_info.extend_from_slice(ctx);

    let mut k = vec![0u8; k_prime.len()];
    hk.expand(&shared_info, &mut k).expect("HKDF expand for k");

    // c = t || c'
    let mut c = t.to_vec();
    c.extend_from_slice(&c_prime);

    (k, c)
}

/// Sub-Kem-Encaps: derive ephemeral key from ikm, compute ECDH.
fn sub_kem_encaps(pk: &PublicKey, ikm: &[u8], _ctx_sub: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // DST = "ARKG-KEM-ECDH-KG." || DST_ext
    // where DST_ext = "ARKG-ECDH.ARKG-P256"
    let dst_kem_kg = b"ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256";

    // sk' = hash_to_field(ikm, 1) with DST = dst_kem_kg
    let sk_scalar = hash_to_scalar(ikm, dst_kem_kg);
    let nz_scalar = NonZeroScalar::<p256::NistP256>::new(sk_scalar)
        .expect("hash_to_field should never produce zero");
    let sk_prime = SecretKey::from(nz_scalar);
    let pk_prime = sk_prime.public_key();

    // k = ECDH(pk, sk')
    let shared_secret =
        elliptic_curve::ecdh::diffie_hellman(sk_prime.to_nonzero_scalar(), pk.as_affine());
    let k = shared_secret.raw_secret_bytes().to_vec();

    // c = uncompressed point encoding of pk'
    let c = pk_prime.to_encoded_point(false).as_bytes().to_vec();

    (k, c)
}

/// BL-PRF: hash_to_field to derive the blinding scalar tau.
/// DST_tau = "ARKG-BL-EC." || DST_ext || ctx
/// where DST_ext = "ARKG-P256"
fn bl_prf(ikm_tau: &[u8], ctx_bl: &[u8]) -> Scalar {
    let mut dst = b"ARKG-BL-EC.ARKG-P256".to_vec();
    dst.extend_from_slice(ctx_bl);

    hash_to_scalar(ikm_tau, &dst)
}

/// hash_to_field for P-256 scalars using expand_message_xmd(SHA-256).
fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    let mut out = [Scalar::ZERO];
    elliptic_curve::hash2curve::hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(
        &[msg],
        &[dst],
        &mut out,
    )
    .expect("hash_to_field");
    out[0]
}

/// Verify an ECDSA signature (in DER format) over a message using a P-256 key.
pub fn verify_signature(pk: &PublicKey, message: &[u8], signature: &[u8]) {
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let vk = VerifyingKey::from(pk);
    let sig = Signature::from_der(signature).expect("signature should be valid DER-encoded ECDSA");
    vk.verify(message, &sig)
        .expect("signature verification failed");
}

// ─── Test vectors from python-fido2 ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVector {
        ctx: &'static [u8],
        pk_bl: &'static str,
        pk_kem: &'static str,
        ikm: &'static str,
        pk_prime: &'static str,
    }

    const TEST_VECTORS: &[TestVector] = &[
        TestVector {
            ctx: b"ARKG-P256.test vectors",
            pk_bl: "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
            pk_kem: "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
            ikm: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            pk_prime: "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd",
        },
        TestVector {
            ctx: b"ARKG-P256.test vectors",
            pk_bl: "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
            pk_kem: "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
            ikm: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            pk_prime: "04ea7d962c9f44ffe8b18f1058a471f394ef81b674948eefc1865b5c021cf858f577f9632b84220e4a1444a20b9430b86731c37e4dcb285eda38d76bf758918d86",
        },
        TestVector {
            ctx: b"ARKG-P256.test vectors.0",
            pk_bl: "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
            pk_kem: "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
            ikm: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            pk_prime: "04b79b65d6bbb419ff97006a1bd52e3f4ad53042173992423e06e52987a037cb61dd82b126b162e4e7e8dc5c9fd86e82769d402a1968c7c547ef53ae4f96e10b0e",
        },
    ];

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_derive_public_key_vectors() {
        for (i, tv) in TEST_VECTORS.iter().enumerate() {
            let pk_bl_bytes = hex_to_bytes(tv.pk_bl);
            let pk_kem_bytes = hex_to_bytes(tv.pk_kem);
            let ikm = hex_to_bytes(tv.ikm);
            let expected_pk = hex_to_bytes(tv.pk_prime);

            let master = ArkgMasterKey::from_raw_keys(&pk_bl_bytes, &pk_kem_bytes);
            let (derived_pk, _args) = derive_public_key(&master, &ikm, tv.ctx);

            let derived_bytes = derived_pk.to_encoded_point(false).as_bytes().to_vec();
            assert_eq!(
                derived_bytes, expected_pk,
                "test vector {i}: derived public key mismatch"
            );
        }
    }
}
