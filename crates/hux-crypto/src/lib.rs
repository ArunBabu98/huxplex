//! Huxplex Layer 0 — post-quantum cryptographic primitives.
//!
//! ML-DSA-44 signatures, ML-KEM-768 key encapsulation with directional HKDF session-key
//! derivation, BIP32 → ML-DSA seed derivation with key purposes, and domain-separated context
//! strings. The versioned algorithm registry that makes all of this rotatable arrives at gate
//! **G1**; see `docs/18-implementation-plan/02-g1-crypto-core.md`.
//!
//! All cryptographic backends are selected at runtime and are architecture-portable; see the
//! backend note in [`kem`].

pub mod bip32;
pub mod error;
pub mod privatekey;
pub mod publickey;
pub mod signature;
pub mod signaturescheme;
pub mod suite;
pub mod traits;

/// Raw primitives. These modules are the **only** places permitted to name a vendor crate
/// (`libcrux_ml_dsa`, `libcrux_ml_kem`); everything above reaches them through the suite
/// registry and the primitive traits (G1 task C4, enforced by
/// `scripts/check-primitive-encapsulation.sh`).
pub mod kem {
    pub mod ml_kem;
    // Re-exported so `hux_crypto::kem::kem768_*` keeps working: the move into `kem/ml_kem.rs`
    // is about where the vendor crate may be named, not a public-API change.
    pub use ml_kem::*;
}
pub mod sig {
    pub mod ml_dsa;
}

// API contracts for primitives that are specified and test-covered but NOT yet implemented.
// They are `#[cfg(test)]` so the conformance suites below type-check against a fixed
// signature, while no `unimplemented!()` cryptography is reachable from the library's public
// API. Their tests are `#[ignore]`d and carry a `// GATE: Gn` marker naming the gate that
// un-ignores them (docs/16-action-plan.md, rule G0-T3).
//
//   slh_dsa  — GATE: G1   (FIPS 205, validator long-lived identity)
//   lb_vrf   — GATE: G6+  (leader election; deferred out of v1)
//   pq_ssle  — GATE: G6+  (single secret leader election; deferred out of v1)
//   zk_stark — GATE: G10  (agent proof-of-task-completion; deferred out of v1)
#[cfg(test)]
pub mod lb_vrf;
#[cfg(test)]
pub mod pq_ssle;
#[cfg(test)]
pub mod slh_dsa;
#[cfg(test)]
pub mod zk_stark;
