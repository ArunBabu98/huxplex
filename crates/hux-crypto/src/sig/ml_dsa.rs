//! ML-DSA-44 (FIPS 204, Dilithium2) — the raw primitive.
//!
//! **This module is the only place in the workspace permitted to name `libcrux_ml_dsa`.**
//! Everything above it reaches ML-DSA through the suite registry
//! (`crate::suite`) and the [`Signer`](crate::traits::Signer) /
//! [`Verifier`](crate::traits::Verifier) traits. That rule is G1 task C4, and it is enforced
//! mechanically by `scripts/check-primitive-encapsulation.sh` rather than by convention —
//! a primitive reachable by a direct call is a primitive that will be called directly.
//!
//! Sizes are FIPS 204 Table 2 and are asserted by the conformance suite
//! (`docs/15-specifications/02-cryptography-spec.md` §2).

use libcrux_ml_dsa::ml_dsa_44;

use crate::error::{CryptoError, CryptoResult};

/// Verification (public) key length.
pub const PK_LEN: usize = 1312;
/// Signing (secret) key length.
pub const SK_LEN: usize = 2560;
/// Signature length.
pub const SIG_LEN: usize = 2420;
/// Key-generation seed length.
pub const SEED_LEN: usize = 32;
/// Per-signature randomness length (hedged signing).
pub const SIGNING_RANDOMNESS_LEN: usize = 32;

/// Deterministically derives a keypair from `seed`, returning `(public, secret)`.
pub fn generate(seed: [u8; SEED_LEN]) -> (Vec<u8>, Vec<u8>) {
    let keypair = ml_dsa_44::generate_key_pair(seed);
    (
        keypair.verification_key.as_ref().to_vec(),
        keypair.signing_key.as_ref().to_vec(),
    )
}

/// Signs `message` under `context` with the supplied per-signature `randomness`.
///
/// Randomness is a parameter rather than drawn here so that the caller decides its source.
/// Production callers MUST pass system CSPRNG output; see G1 task C9, which splits the public
/// entry points so a caller-supplied value cannot reach production signing.
pub fn sign(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: [u8; SIGNING_RANDOMNESS_LEN],
) -> CryptoResult<Vec<u8>> {
    let sk_bytes: [u8; SK_LEN] = secret_key
        .try_into()
        .map_err(|e| CryptoError::InvalidSecretKeySize(format!("{e:?}")))?;

    let signing_key = ml_dsa_44::MLDSA44SigningKey::new(sk_bytes);

    let signature = ml_dsa_44::sign(&signing_key, message, context, randomness)
        .map_err(|e| CryptoError::SigningFailed(format!("{e:?}")))?;

    Ok(signature.as_ref().to_vec())
}

/// Verifies `signature` over `message` under `context`.
///
/// Returns `Ok(false)` for a well-formed signature that does not verify, and `Err` only when an
/// input is structurally wrong (bad length). Callers MUST NOT treat the two as interchangeable.
pub fn verify(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let pk_bytes: [u8; PK_LEN] = public_key.try_into().map_err(|_| {
        CryptoError::InvalidPublicKeySize(format!(
            "Expected {PK_LEN} bytes, got {}",
            public_key.len()
        ))
    })?;

    let sig_bytes: [u8; SIG_LEN] =
        signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignatureLength {
                expected: SIG_LEN,
                actual: signature.len(),
            })?;

    let verification_key = ml_dsa_44::MLDSA44VerificationKey::new(pk_bytes);
    let signature = ml_dsa_44::MLDSA44Signature::new(sig_bytes);

    Ok(ml_dsa_44::verify(&verification_key, message, context, &signature).is_ok())
}
