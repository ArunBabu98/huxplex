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
//! **[`Kem`] landed with the hybrid KEX** (G1 task B5), once there were two implementations —
//! ML-KEM-768 and X25519 + ML-KEM-768 — for its shape to be drawn from. **`Hasher` is still
//! deliberately absent**: SHAKE-256 is its only implementation until BLAKE3 arrives at G2b, and a
//! trait written against one implementation encodes that implementation's shape.

use rand::Rng;
use zeroize::Zeroizing;

use crate::{
    error::CryptoResult,
    suite::{KemId, SignatureSchemeId, SuiteError},
};

/// Each scheme's trait implementation lives beside its primitive, so registering a scheme is
/// its own module, a registry row and a dispatch arm below — never a size edit anywhere else
/// (G1 task C6). Re-exported so `hux_crypto::traits::MlDsa44` keeps working.
pub use crate::{
    kem::{MlKem768, hybrid::X25519MlKem768},
    sig::{ml_dsa::MlDsa44, slh_dsa::SlhDsaShake128s},
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

/// Byte lengths a KEM fixes — the [`SchemeSizes`] of key agreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KemSizes {
    pub encapsulation_key: usize,
    pub decapsulation_key: usize,
    pub ciphertext: usize,
    pub shared_secret: usize,
    pub keygen_seed: usize,
    pub encaps_randomness: usize,
}

/// Key encapsulation.
///
/// `encapsulate_derand` takes its randomness explicitly — FIPS 203's `Encaps_internal` shape,
/// which is what KATs need. Unlike signing there is no fault-attack argument for sealing it, but
/// reused randomness against one key *does* repeat the shared secret, so production callers use
/// [`encapsulate`], which draws it from the system CSPRNG.
pub trait Kem {
    fn sizes(&self) -> KemSizes;

    /// `(encapsulation_key, decapsulation_key)`, deterministic in `seed`.
    fn generate(&self, seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)>;

    /// `(ciphertext, shared_secret)`, deterministic in `randomness`.
    fn encapsulate_derand(
        &self,
        encapsulation_key: &[u8],
        randomness: &[u8],
    ) -> CryptoResult<(Vec<u8>, [u8; 32])>;

    fn decapsulate(&self, decapsulation_key: &[u8], ciphertext: &[u8]) -> CryptoResult<[u8; 32]>;
}

/// Resolves a KEM identifier to its implementation. Total: every registered KEM is implemented.
pub fn kem(id: KemId) -> &'static dyn Kem {
    match id {
        KemId::MlKem768 => &MlKem768,
        KemId::X25519MlKem768 => &X25519MlKem768,
    }
}

/// Production encapsulation: randomness from the system CSPRNG, sized by the KEM's descriptor.
pub fn encapsulate(kem: &dyn Kem, encapsulation_key: &[u8]) -> CryptoResult<(Vec<u8>, [u8; 32])> {
    let mut randomness = Zeroizing::new(vec![0u8; kem.sizes().encaps_randomness]);
    rand::rng().fill_bytes(&mut randomness);
    kem.encapsulate_derand(encapsulation_key, &randomness)
}
