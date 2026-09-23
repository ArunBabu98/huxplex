//! The primitive traits — the only path from the registry to an implementation.
//!
//! G1 task C4: *"no direct call to a named scheme outside the registry."* The registry resolves
//! `(role, version)` to a [`SignatureSchemeId`]; these traits turn that identifier into an
//! operation. Nothing above this layer names `sig::ml_dsa` or `kem::ml_kem`, and
//! `scripts/check-primitive-encapsulation.sh` enforces it.
//!
//! **Why [`Signer`] and [`Verifier`] are separate.** Verifying is not signing: a light client,
//! an archival verifier, or a node validating history under a retired suite must verify without
//! any capacity to sign. Splitting the traits lets a scheme be registered verify-only — which is
//! exactly what a deprecated-but-still-verifiable suite version needs (ADR-0018 rule V5, *old
//! pairs stay verifiable forever*). Merging them would make "can verify" imply "can sign", and
//! that implication is false for most of a chain's lifetime.
//!
//! **`Kem` and `Hasher` are deliberately not here yet.** The G1 plan lists them, but each has
//! exactly one candidate implementation today (ML-KEM-768, SHAKE-256) and no second in prospect
//! before G5. A trait written against one implementation encodes that implementation's shape and
//! has to be redesigned when the second arrives; the encapsulation check already confines both
//! vendor crates, which is the property C4 actually asks for. They land with the hybrid KEX and
//! BLAKE3 respectively.

use crate::{
    error::{CryptoError, CryptoResult},
    sig::ml_dsa,
    suite::{SignatureSchemeId, SuiteError},
};

/// Byte lengths a scheme fixes. Sourced from the descriptor so no call site needs a literal
/// (G1 task C6 — *"a second signature scheme can be registered without editing any size
/// literal"*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemeSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
    pub seed: usize,
}

/// Verification, and the sizes needed to check inputs before attempting it.
pub trait Verifier {
    fn sizes(&self) -> SchemeSizes;

    /// Returns `Ok(false)` for a well-formed signature that does not verify, and `Err` only when
    /// an input is structurally wrong. Callers MUST NOT collapse the two: a length error treated
    /// as a verification failure hides malformed input, and the reverse turns a forgery into a
    /// parse error.
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool>;
}

/// Key generation and signing — the capability a verify-only deployment must not have.
pub trait Signer {
    fn generate(&self, seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)>;

    /// `randomness` is a parameter so the caller decides its source. Production callers MUST pass
    /// system CSPRNG output; G1 task C9 splits the public entry points so a caller-supplied value
    /// cannot reach production signing.
    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        randomness: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

/// A scheme that can do both. The registry hands back this combined view; code that only needs
/// one half can take `&dyn Verifier` or `&dyn Signer` instead.
pub trait SignatureScheme: Signer + Verifier {}

impl<T: Signer + Verifier> SignatureScheme for T {}

/// ML-DSA-44 (FIPS 204).
pub struct MlDsa44;

impl Verifier for MlDsa44 {
    fn sizes(&self) -> SchemeSizes {
        SchemeSizes {
            public_key: ml_dsa::PK_LEN,
            secret_key: ml_dsa::SK_LEN,
            signature: ml_dsa::SIG_LEN,
            seed: ml_dsa::SEED_LEN,
        }
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        ml_dsa::verify(public_key, message, context, signature)
    }
}

impl Signer for MlDsa44 {
    fn generate(&self, seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let seed: [u8; ml_dsa::SEED_LEN] =
            seed.try_into().map_err(|_| CryptoError::InvalidKeyLength {
                expected: ml_dsa::SEED_LEN,
                actual: seed.len(),
            })?;
        Ok(ml_dsa::generate(seed))
    }

    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        randomness: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let randomness: [u8; ml_dsa::SIGNING_RANDOMNESS_LEN] =
            randomness
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength {
                    expected: ml_dsa::SIGNING_RANDOMNESS_LEN,
                    actual: randomness.len(),
                })?;
        ml_dsa::sign(secret_key, message, context, randomness)
    }
}

/// Resolves an identifier to its implementation.
///
/// Returns [`SuiteError::SchemeUnimplemented`] for a scheme that is registered but not built yet
/// — suite v1 resolves `Identity` and `Governance` to SLH-DSA-128s, which arrives at G1 task C7.
/// That is a *distinct* error from an unknown identifier, and neither ever falls back to a
/// working scheme: silently substituting a hot-path primitive for a root-of-trust one is the
/// downgrade this registry exists to prevent.
pub fn implementation(
    scheme: SignatureSchemeId,
) -> Result<&'static dyn SignatureScheme, SuiteError> {
    match scheme {
        SignatureSchemeId::Dilithium2 => Ok(&MlDsa44),
        SignatureSchemeId::SlhDsa128s => Err(SuiteError::SchemeUnimplemented { scheme }),
    }
}

/// Resolves an identifier to verification only.
///
/// Prefer this wherever signing is not required — a verifier handle cannot sign, which makes the
/// absence of that capability a type-level fact rather than a review comment.
pub fn verifier(scheme: SignatureSchemeId) -> Result<&'static dyn Verifier, SuiteError> {
    match scheme {
        SignatureSchemeId::Dilithium2 => Ok(&MlDsa44),
        SignatureSchemeId::SlhDsa128s => Err(SuiteError::SchemeUnimplemented { scheme }),
    }
}
