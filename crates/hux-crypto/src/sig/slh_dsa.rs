//! SLH-DSA-SHAKE-128s (FIPS 205) — the raw primitive.
//!
//! **This module is the only place in the workspace permitted to name `fips205`** (G1 task C4,
//! enforced by `scripts/check-primitive-encapsulation.sh`). Everything above it reaches SLH-DSA
//! through the suite registry and the [`Signer`] / [`Verifier`] traits.
//!
//! # Which instantiation, and why
//!
//! Suite v1 binds the long-lived roles — `Identity` and `Governance` — to "SLH-DSA-128s"
//! (crypto spec §1.1, ADR-0018). FIPS 205 defines that parameter set over two hash families;
//! this is the **SHAKE** one. SHAKE-256 is already the identity hash domain
//! ([ADR-0010](../../../../docs/adr/0010-hash-function-domains.md)) — `PeerId` and
//! `did:huxplex` both derive through it — so the root-of-trust signature rests on the same
//! hash assumption as the identities it signs for, rather than adding SHA-2 as a second one.
//!
//! # Implementation
//!
//! [`fips205`](https://crates.io/crates/fips205): pure Rust, `#![deny(unsafe_code)]`, constant
//! time with respect to secret data. Cross-checked byte for byte against RustCrypto `slh-dsa` in
//! `tests/slh_dsa_differential.rs` (G1 task C8) — a dev-dependency only.
//!
//! # Keygen seed
//!
//! FIPS 205 Algorithm 18 draws three `n`-byte values, in order: `SK.seed`, `SK.prf`, `PK.seed`.
//! The 48-byte seed this module takes is exactly that concatenation, so a key is reproducible
//! from it by any conforming implementation.

use fips205::{
    slh_dsa_shake_128s as slh,
    traits::{KeyGen, SerDes, Signer as _, Verifier as _},
};
use rand_core_06::{CryptoRng, RngCore};

use crate::{
    error::{CryptoError, CryptoResult},
    traits::{SchemeSizes, Signer, SigningRandomness, Verifier},
};

/// Security parameter `n` for the 128-bit sets (FIPS 205 Table 2).
const N: usize = 16;

/// Verification (public) key length: `PK.seed ‖ PK.root` = `2n`.
pub const PK_LEN: usize = 32;
/// Signing (secret) key length: `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` = `4n`.
pub const SK_LEN: usize = 64;
/// Signature length (FIPS 205 Table 2, SLH-DSA-128s).
pub const SIG_LEN: usize = 7856;
/// Keygen seed length: `SK.seed ‖ SK.prf ‖ PK.seed` = `3n`.
pub const SEED_LEN: usize = 3 * N;
/// Hedged-signing randomness: FIPS 205 Algorithm 22's `opt_rand`, `n` bytes.
pub const SIGNING_RANDOMNESS_LEN: usize = N;

// The sizes above are this crate's contract; the vendor's are its implementation. If a fips205
// release ever disagreed, the build stops here rather than on the network.
const _: () = {
    assert!(PK_LEN == slh::PK_LEN);
    assert!(SK_LEN == slh::SK_LEN);
    assert!(SIG_LEN == slh::SIG_LEN);
};

/// Deterministically derives a keypair from `seed`, returning `(public, secret)`.
pub fn generate(seed: [u8; SEED_LEN]) -> (Vec<u8>, Vec<u8>) {
    let mut part = [[0u8; N]; 3];
    for (i, chunk) in seed.chunks_exact(N).enumerate() {
        part[i].copy_from_slice(chunk);
    }
    let (pk, sk) = slh::KG::keygen_with_seeds(&part[0], &part[1], &part[2]);
    (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
}

/// Signs `message` under `context` with the supplied `opt_rand`.
///
/// Crate-private for the same reason as `ml_dsa::sign`: the only caller is
/// [`SlhDsaShake128s`]'s [`Signer`] impl, whose randomness only this crate can construct
/// (G1 task C9).
pub(crate) fn sign(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
    opt_rand: [u8; SIGNING_RANDOMNESS_LEN],
) -> CryptoResult<Vec<u8>> {
    let sk_bytes: [u8; SK_LEN] = secret_key.try_into().map_err(|_| {
        CryptoError::InvalidSecretKeySize(format!(
            "Expected {SK_LEN} bytes, got {}",
            secret_key.len()
        ))
    })?;
    // `try_from_bytes` recomputes PK.root from the seeds and rejects a key that does not match,
    // so a corrupted secret key fails here instead of producing signatures that never verify.
    let sk = slh::PrivateKey::try_from_bytes(&sk_bytes)
        .map_err(|e| CryptoError::InvalidSecretKeySize(e.to_string()))?;

    let mut rng = OptRand(Some(opt_rand));
    let signature = sk
        .try_sign_with_rng(&mut rng, message, context, true)
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

    Ok(signature.to_vec())
}

/// Verifies `signature` over `message` under `context`.
///
/// Returns `Ok(false)` for a well-formed signature that does not verify, and `Err` only when an
/// input has the wrong length — the same contract as `ml_dsa::verify`.
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

    let pk = slh::PublicKey::try_from_bytes(&pk_bytes)
        .map_err(|e| CryptoError::InvalidPublicKeySize(e.to_string()))?;
    Ok(pk.verify(message, &sig_bytes, context))
}

/// Hands fips205 exactly one `opt_rand` and nothing else.
///
/// fips205 takes randomness as an RNG; Huxplex takes it as a [`SigningRandomness`] value so that
/// its source is decided — and sealed — in one place. This adapter is the bridge: it yields the
/// one `n`-byte value it was built with, and fails any other request rather than inventing bytes.
/// A second draw, or a draw of a different length, would mean the vendor's signing path changed
/// shape, and that must be an error, not silently predictable output.
struct OptRand(Option<[u8; N]>);

impl RngCore for OptRand {
    fn next_u32(&mut self) -> u32 {
        unreachable!("fips205 draws opt_rand through try_fill_bytes only")
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!("fips205 draws opt_rand through try_fill_bytes only")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        unreachable!("fips205 draws opt_rand through try_fill_bytes only")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        match self.0.take() {
            Some(bytes) if dest.len() == N => {
                dest.copy_from_slice(&bytes);
                Ok(())
            }
            _ => Err(rand_core_06::Error::from(
                core::num::NonZeroU32::new(rand_core_06::Error::CUSTOM_START).unwrap(),
            )),
        }
    }
}

impl CryptoRng for OptRand {}

/// SLH-DSA-SHAKE-128s behind the registry's traits.
pub struct SlhDsaShake128s;

impl Verifier for SlhDsaShake128s {
    fn sizes(&self) -> SchemeSizes {
        SchemeSizes {
            public_key: PK_LEN,
            secret_key: SK_LEN,
            signature: SIG_LEN,
            seed: SEED_LEN,
            signing_randomness: SIGNING_RANDOMNESS_LEN,
        }
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        verify(public_key, message, context, signature)
    }
}

impl Signer for SlhDsaShake128s {
    fn generate(&self, seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let seed: [u8; SEED_LEN] = seed.try_into().map_err(|_| CryptoError::InvalidKeyLength {
            expected: SEED_LEN,
            actual: seed.len(),
        })?;
        Ok(generate(seed))
    }

    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        randomness: &SigningRandomness,
    ) -> CryptoResult<Vec<u8>> {
        let randomness = randomness.as_bytes();
        let opt_rand: [u8; SIGNING_RANDOMNESS_LEN] =
            randomness
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength {
                    expected: SIGNING_RANDOMNESS_LEN,
                    actual: randomness.len(),
                })?;
        sign(secret_key, message, context, opt_rand)
    }
}
