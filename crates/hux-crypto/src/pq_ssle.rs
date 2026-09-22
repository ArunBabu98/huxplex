//! PQ-SSLE (post-quantum single secret leader election) — API contract only.
//! **Not implemented.**
//!
//! Elects exactly one leader per slot such that only the leader learns it is the
//! leader until it reveals. Explicitly **deferred out of v1**
//! (docs/15-specifications/06-v1-scope.md §3).
//!
//! `#[cfg(test)]`-only; exists so `pq_ssle_tests` type-checks against a fixed contract.
//!
//! Gate: **G6+**.

/// SSLE public key.
pub type SslePublicKey = [u8; 32];
/// SSLE secret key.
pub type SsleSecretKey = [u8; 32];

/// A validator's per-epoch commitment, as placed into the shuffled slot list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsleCommitment {
    pub bytes: Vec<u8>,
}

/// Proof that the holder of a secret key owns a given shuffled commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsleReveal {
    pub bytes: Vec<u8>,
}

const UNIMPLEMENTED: &str = "PQ-SSLE is not implemented (gate G6+). See docs/16-action-plan.md.";

/// Derive an SSLE keypair from a seed. MUST be deterministic in the seed.
pub fn ssle_keygen(_seed: [u8; 32]) -> (SslePublicKey, SsleSecretKey) {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Produce this validator's commitment for the given epoch.
pub fn ssle_commit(_sk: &SsleSecretKey, _epoch_seed: [u8; 32]) -> SsleCommitment {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Shuffle the epoch's commitments into slot order. MUST be deterministic in
/// `epoch_seed` and MUST preserve the multiset of commitments.
pub fn ssle_shuffle(_commitments: &[SsleCommitment], _epoch_seed: [u8; 32]) -> Vec<SsleCommitment> {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Attempt to claim `slot`. Returns `Some(reveal)` only for the owning validator.
pub fn ssle_try_reveal(_sk: &SsleSecretKey, _slot: &SsleCommitment) -> Option<SsleReveal> {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Verify that `reveal` proves `pk` owns `slot`.
pub fn ssle_verify_leader(
    _pk: &SslePublicKey,
    _slot: &SsleCommitment,
    _reveal: &SsleReveal,
) -> bool {
    unimplemented!("{UNIMPLEMENTED}")
}
