//! SHAKE-256 (FIPS 202) — the raw primitive.
//!
//! **This module is the only place in the workspace permitted to name `libcrux_sha3`**, the same
//! rule `sig/ml_dsa.rs` and `kem/ml_kem.rs` carry for their vendors (G1 task C4, enforced by
//! `scripts/check-primitive-encapsulation.sh`).
//!
//! # Why libcrux rather than RustCrypto `sha3`
//!
//! `libcrux-sha3` was **already in the dependency tree**, pulled by both `libcrux-ml-dsa` and
//! `libcrux-ml-kem`, so using it directly costs nothing new in supply chain — and it removes the
//! RustCrypto `sha3` dependency from the workspace entirely. It is also the formally-verified
//! vendor the dependency policy already names for the post-quantum primitives, which matters
//! more here than it might elsewhere: SHAKE-256 defines **peer identity**
//! (`PeerId = SHAKE-256(ml_dsa_pk)[..32]`), so it is identity-critical rather than incidental.
//!
//! The migration was proven byte-neutral before it was made — see
//! `tests/kat_hashes.rs`, whose vectors were generated from the previous implementation and must
//! continue to hold.

/// SHAKE-256 squeezed to `N` bytes.
///
/// One absorb, one squeeze. Callers that need a different output length pick `N`; nothing here
/// is specialised to 32 bytes beyond the convenience wrapper below.
pub fn shake256<const N: usize>(data: &[u8]) -> [u8; N] {
    libcrux_sha3::shake256::<N>(data)
}

/// SHAKE-256 squeezed to 32 bytes — the length `PeerId` and the identity hash domain use
/// ([ADR-0010](../../../../docs/adr/0010-hash-function-domains.md)).
pub fn shake256_32(data: &[u8]) -> [u8; 32] {
    shake256::<32>(data)
}
