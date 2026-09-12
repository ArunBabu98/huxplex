//! SLH-DSA-128s (FIPS 205) — API contract only. **Not implemented.**
//!
//! Hash-based stateless signatures, used for validator long-lived identity and
//! root-of-trust, per ADR-0002's hybrid key model (ML-DSA-44 hot signing,
//! SLH-DSA long-lived identity).
//!
//! This module exists so the conformance suite in `mod.rs` (`slh_dsa_128s_tests`)
//! type-checks against a fixed contract before there is an implementation. It is
//! `#[cfg(test)]`-only: no `unimplemented!()` cryptography is exposed in the
//! library's public API.
//!
//! Gate: **G1** (docs/16-action-plan.md). Implementing this module means making
//! `slh_dsa_128s_tests` pass and removing the `#[ignore]` markers.

/// FIPS 205 Table 1, SLH-DSA-128s: `PKBytes = 2n = 32`.
pub const SLH_DSA_PK_SIZE: usize = 32;
/// FIPS 205 Table 1, SLH-DSA-128s: `SKBytes = 4n = 64`.
pub const SLH_DSA_SK_SIZE: usize = 64;
/// FIPS 205 Table 1, SLH-DSA-128s: `SigBytes = 7856`.
pub const SLH_DSA_SIG_SIZE: usize = 7856;

const UNIMPLEMENTED: &str =
    "SLH-DSA-128s is not implemented (gate G1). See docs/16-action-plan.md.";

/// Derive a keypair from a FIPS 205 keygen seed
/// (`SK.seed(n) || SK.prf(n) || PK.seed(n)` = 3n = 48 bytes for n=16).
pub fn slh_dsa_128s_keygen(_seed: [u8; 48]) -> ([u8; SLH_DSA_PK_SIZE], [u8; SLH_DSA_SK_SIZE]) {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Sign `msg` under optional domain-separation context `ctx`.
pub fn slh_dsa_128s_sign(
    _sk: &[u8; SLH_DSA_SK_SIZE],
    _msg: &[u8],
    _ctx: Option<&[u8]>,
) -> [u8; SLH_DSA_SIG_SIZE] {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Verify `sig` over `msg` under the same context used to sign.
pub fn slh_dsa_128s_verify(
    _pk: &[u8; SLH_DSA_PK_SIZE],
    _msg: &[u8],
    _sig: &[u8; SLH_DSA_SIG_SIZE],
    _ctx: Option<&[u8]>,
) -> bool {
    unimplemented!("{UNIMPLEMENTED}")
}
