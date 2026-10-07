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

use rand::Rng;
use zeroize::Zeroizing;

use crate::{
    error::CryptoResult,
    suite::{SignatureSchemeId, SuiteError},
};

/// Each scheme's trait implementation lives beside its primitive, so registering a scheme is
/// its own module, a registry row and a dispatch arm below — never a size edit anywhere else
/// (G1 task C6). Re-exported so `hux_crypto::traits::MlDsa44` keeps working.
pub use crate::sig::{ml_dsa::MlDsa44, slh_dsa::SlhDsaShake128s};

/// Byte lengths a scheme fixes. Sourced from the descriptor so no call site needs a literal
/// (G1 task C6 — *"a second signature scheme can be registered without editing any size
/// literal"*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemeSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
    pub seed: usize,
    /// Per-signature randomness the scheme consumes (hedged signing). The signing path reads
    /// this rather than naming a constant, so a scheme with a different nonce length — SLH-DSA's
    /// `opt_rand` is `n` bytes, ML-DSA's `rnd` is 32 — needs no edit outside its own module.
    pub signing_randomness: usize,
}

/// Per-signature randomness for hedged signing.
///
/// **Constructible only inside `hux-crypto`.** Production code obtains it from the system CSPRNG
/// via the signing path; the explicit-bytes constructor exists only under `cfg(test)`, for the
/// byte-exact signature KATs. Two constructors, not one with a flag — a `deterministic: bool` is
/// a downgrade switch waiting for a misconfiguration, and deterministic lattice signing plus fault
/// injection is a demonstrated key-recovery path (eprint 2025/2009).
///
/// Neither constructor is reachable from outside the crate:
///
/// ```compile_fail
/// let _ = hux_crypto::traits::SigningRandomness::from_system_rng(32);
/// ```
///
/// ```compile_fail
/// let _ = hux_crypto::traits::SigningRandomness::explicit(&[0u8; 32]);
/// ```
pub struct SigningRandomness(Zeroizing<Vec<u8>>);

impl SigningRandomness {
    /// `len` fresh bytes from the system CSPRNG. The production constructor.
    pub(crate) fn from_system_rng(len: usize) -> Self {
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Caller-chosen bytes. **Test-only** — compiled out of every non-test build, so it cannot
    /// reach production signing by any route.
    #[cfg(test)]
    pub(crate) fn explicit(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    /// Read access for scheme implementations.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
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

    /// Signs with the supplied per-signature randomness.
    ///
    /// The parameter is a [`SigningRandomness`], which **only this crate can construct** — from
    /// the system CSPRNG in production, or from explicit bytes in this crate's own tests. So the
    /// trait can be public (a downstream crate may implement a scheme) without being a path by
    /// which a caller chooses the nonce (G1 task C9, crypto spec §3).
    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        randomness: &SigningRandomness,
    ) -> CryptoResult<Vec<u8>>;
}

/// A scheme that can do both. The registry hands back this combined view; code that only needs
/// one half can take `&dyn Verifier` or `&dyn Signer` instead.
pub trait SignatureScheme: Signer + Verifier {}

impl<T: Signer + Verifier> SignatureScheme for T {}

/// Resolves an identifier to its implementation.
///
/// Every scheme suite v1 names is implemented. A scheme registered ahead of its implementation
/// would resolve to [`SuiteError::SchemeUnimplemented`] — a *distinct* error from an unknown
/// identifier, and never a fallback to a working scheme: silently substituting a hot-path
/// primitive for a root-of-trust one is the downgrade this registry exists to prevent.
pub fn implementation(
    scheme: SignatureSchemeId,
) -> Result<&'static dyn SignatureScheme, SuiteError> {
    match scheme {
        SignatureSchemeId::Dilithium2 => Ok(&MlDsa44),
        SignatureSchemeId::SlhDsa128s => Ok(&SlhDsaShake128s),
    }
}

/// Resolves an identifier to verification only.
///
/// Prefer this wherever signing is not required — a verifier handle cannot sign, which makes the
/// absence of that capability a type-level fact rather than a review comment.
pub fn verifier(scheme: SignatureSchemeId) -> Result<&'static dyn Verifier, SuiteError> {
    match scheme {
        SignatureSchemeId::Dilithium2 => Ok(&MlDsa44),
        SignatureSchemeId::SlhDsa128s => Ok(&SlhDsaShake128s),
    }
}
