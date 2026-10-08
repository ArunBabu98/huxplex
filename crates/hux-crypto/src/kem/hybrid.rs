//! X25519 + ML-KEM-768 hybrid key encapsulation — **G1 task B5**, gate test **G1-T5**.
//!
//! [ADR-0002](../../../../docs/adr/0002-cryptographic-parameter-set.md) fixes transport key
//! agreement for suite v1 as *"ML-KEM-768 + X25519 (hybrid)"*: an attacker must break **both**
//! halves. A future quantum computer breaks X25519 and leaves ML-KEM standing; a future
//! cryptanalytic break of ML-KEM leaves X25519 standing.
//!
//! # Where this is used
//!
//! Not on the transport: [ADR-0019](../../../../docs/adr/0019-transport-authentication.md) gives
//! the QUIC handshake to rustls, which performs TLS's own `X25519MLKEM768`. This is the
//! **application-level** hybrid — for session keys Huxplex derives itself, where
//! `kem768_derive_session_key` alone would be ML-KEM-only.
//!
//! # Construction
//!
//! Byte layout follows TLS `X25519MLKEM768` (draft-ietf-tls-ecdhe-mlkem): the ML-KEM part first,
//! then the X25519 part, in every value.
//!
//! ```text
//! encapsulation key = ek_mlkem (1184)  ‖ pk_x25519 (32)          = 1216
//! decapsulation key = dk_mlkem (2400)  ‖ sk_x25519 (32)          = 2432
//! ciphertext        = ct_mlkem (1088)  ‖ ephemeral pk_x25519 (32) = 1120
//!
//! shared secret = HKDF-SHA-256(
//!     salt = none,
//!     ikm  = ss_mlkem ‖ ss_x25519,
//!     info = "X25519-MLKEM768-v1-COMBINE" ‖ ct_x25519 ‖ pk_x25519,
//! ) -> 32 bytes
//! ```
//!
//! **Why the X25519 values are in `info`.** ML-KEM is IND-CCA, so its shared secret already
//! commits to its ciphertext and key. X25519 is not: its secret is a function of the two points
//! alone. Binding `ct_x25519` and `pk_x25519` into the combiner is what makes the whole construct
//! IND-CCA when only ML-KEM holds — the argument of X-Wing (eprint 2024/039). ML-KEM's secret
//! comes first in `ikm` so the approved component leads, as SP 800-56C's hybrid guidance expects.

use hkdf::Hkdf;
use sha2::Sha256;

use super::{ml_kem, x25519};
use crate::{
    error::{CryptoError, CryptoResult},
    traits::{Kem, KemSizes},
};

/// HKDF `info` prefix for the combiner. A registry entry in crypto spec §5, like
/// `ML-KEM-768-v1-DERIVE`; changing it is a consensus-affecting change and bumps `v1`.
pub const COMBINER_LABEL: &[u8] = b"X25519-MLKEM768-v1-COMBINE";

/// Encapsulation key length.
pub const EK_LEN: usize = ml_kem::EK_SIZE + x25519::KEY_LEN;
/// Decapsulation key length.
pub const DK_LEN: usize = ml_kem::DK_SIZE + x25519::KEY_LEN;
/// Ciphertext length.
pub const CT_LEN: usize = ml_kem::CT_SIZE + x25519::KEY_LEN;
/// Keygen seed: ML-KEM's `d ‖ z` (64) then the X25519 secret scalar (32).
pub const SEED_LEN: usize = 64 + x25519::KEY_LEN;
/// Encapsulation randomness: ML-KEM's `m` (32) then the ephemeral X25519 scalar (32).
pub const ENCAPS_RANDOMNESS_LEN: usize = 32 + x25519::KEY_LEN;
/// Shared secret length.
pub const SS_LEN: usize = 32;

/// The combiner. Crate-visible so G1-T5 can drive it with a broken classical half.
pub(crate) fn combine(
    ss_mlkem: &[u8; 32],
    ss_x25519: &[u8; 32],
    ct_x25519: &[u8; 32],
    pk_x25519: &[u8; 32],
) -> [u8; SS_LEN] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_mlkem);
    ikm[32..].copy_from_slice(ss_x25519);

    let mut info = Vec::with_capacity(COMBINER_LABEL.len() + 64);
    info.extend_from_slice(COMBINER_LABEL);
    info.extend_from_slice(ct_x25519);
    info.extend_from_slice(pk_x25519);

    let mut out = [0u8; SS_LEN];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(&info, &mut out)
        .expect("32 bytes is a valid length for HKDF-SHA256");
    zeroize::Zeroize::zeroize(&mut ikm);
    out
}

/// Splits a hybrid value into its ML-KEM and X25519 parts, rejecting a wrong total length.
fn split<const A: usize, const B: usize>(bytes: &[u8]) -> CryptoResult<([u8; A], [u8; B])> {
    if bytes.len() != A + B {
        return Err(CryptoError::InvalidKeyLength {
            expected: A + B,
            actual: bytes.len(),
        });
    }
    Ok((
        bytes[..A].try_into().unwrap(),
        bytes[A..].try_into().unwrap(),
    ))
}

/// X25519 + ML-KEM-768 behind the [`Kem`] trait.
pub struct X25519MlKem768;

impl Kem for X25519MlKem768 {
    fn sizes(&self) -> KemSizes {
        KemSizes {
            encapsulation_key: EK_LEN,
            decapsulation_key: DK_LEN,
            ciphertext: CT_LEN,
            shared_secret: SS_LEN,
            keygen_seed: SEED_LEN,
            encaps_randomness: ENCAPS_RANDOMNESS_LEN,
        }
    }

    fn generate(&self, seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let (mlkem_seed, x_secret) = split::<64, { x25519::KEY_LEN }>(seed)?;
        let (ek_m, dk_m) = ml_kem::kem768_keygen(mlkem_seed);
        let pk_x = x25519::public_key(&x_secret);

        Ok(([&ek_m[..], &pk_x].concat(), [&dk_m[..], &x_secret].concat()))
    }

    fn encapsulate_derand(
        &self,
        encapsulation_key: &[u8],
        randomness: &[u8],
    ) -> CryptoResult<(Vec<u8>, [u8; SS_LEN])> {
        let (ek_m, pk_x) = split::<{ ml_kem::EK_SIZE }, { x25519::KEY_LEN }>(encapsulation_key)?;
        let (m, eph_secret) = split::<32, { x25519::KEY_LEN }>(randomness)?;

        let (ct_m, ss_m) = ml_kem::kem768_encapsulate(ek_m, m);
        let ct_x = x25519::public_key(&eph_secret);
        let ss_x = x25519::shared_secret(&eph_secret, &pk_x)?;

        Ok((
            [&ct_m[..], &ct_x].concat(),
            combine(&ss_m, &ss_x, &ct_x, &pk_x),
        ))
    }

    fn decapsulate(
        &self,
        decapsulation_key: &[u8],
        ciphertext: &[u8],
    ) -> CryptoResult<[u8; SS_LEN]> {
        let (dk_m, x_secret) =
            split::<{ ml_kem::DK_SIZE }, { x25519::KEY_LEN }>(decapsulation_key)?;
        let (ct_m, ct_x) = split::<{ ml_kem::CT_SIZE }, { x25519::KEY_LEN }>(ciphertext)?;

        let ss_m = ml_kem::kem768_decapsulate(dk_m, ct_m);
        let ss_x = x25519::shared_secret(&x_secret, &ct_x)?;
        let pk_x = x25519::public_key(&x_secret);

        Ok(combine(&ss_m, &ss_x, &ct_x, &pk_x))
    }
}

#[cfg(test)]
mod g1_t5 {
    //! **G1-T5 — the hybrid retains post-quantum security if the classical half is broken.**
    //! *Force X25519's output to a constant; session keys still differ.*
    //!
    //! "Broken" is modelled as the adversary knowing — here, fixing — the X25519 shared secret
    //! and every public X25519 value. What remains secret is ML-KEM's shared secret, and the
    //! combined secret must still depend on it.

    use super::*;
    use crate::kem::kem768_derive_session_key;

    const BROKEN_SS_X: [u8; 32] = [0x00; 32];
    const CT_X: [u8; 32] = [0x09; 32];
    const PK_X: [u8; 32] = [0x09; 32];

    #[test]
    fn g1_t5_session_keys_still_differ_with_x25519_forced_to_a_constant() {
        let (peer_a, peer_b) = ([1u8; 32], [2u8; 32]);
        let mut seen = Vec::new();

        // Five independent ML-KEM exchanges, all with the classical half pinned identically.
        for i in 0..5u8 {
            let (ek, dk) = ml_kem::kem768_keygen([i; 64]);
            let (ct, ss_m) = ml_kem::kem768_encapsulate(ek, [i.wrapping_add(100); 32]);
            assert_eq!(ml_kem::kem768_decapsulate(dk, ct), ss_m);

            let combined = combine(&ss_m, &BROKEN_SS_X, &CT_X, &PK_X);
            let session = kem768_derive_session_key(combined, peer_a, peer_b, None, Some(b"g1-t5"));
            assert!(
                !seen.contains(&session),
                "exchange {i} collided with an earlier one"
            );
            seen.push(session);
        }
    }

    #[test]
    fn g1_t5_every_ml_kem_bit_reaches_the_combined_secret() {
        // Stronger than "differs for different keypairs": a single-bit change anywhere in the
        // ML-KEM secret changes the output, with the classical half held constant.
        let base = [0x5Au8; 32];
        let reference = combine(&base, &BROKEN_SS_X, &CT_X, &PK_X);
        for byte in 0..32 {
            for bit in 0..8 {
                let mut ss_m = base;
                ss_m[byte] ^= 1 << bit;
                assert_ne!(combine(&ss_m, &BROKEN_SS_X, &CT_X, &PK_X), reference);
            }
        }
    }

    #[test]
    fn g1_t5_the_combined_secret_is_not_the_ml_kem_secret() {
        // The combiner must not pass either input through — otherwise "hybrid" is ML-KEM with
        // extra steps and the classical half contributes nothing even when it is sound.
        let ss_m = [0x77u8; 32];
        let ss_x = [0x33u8; 32];
        let out = combine(&ss_m, &ss_x, &CT_X, &PK_X);
        assert_ne!(out, ss_m);
        assert_ne!(out, ss_x);
        assert_ne!(out, combine(&ss_m, &[0x34u8; 32], &CT_X, &PK_X));
    }
}
