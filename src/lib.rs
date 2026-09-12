//! Huxplex — post-quantum cryptographic and networking primitives.
//!
//! Current scope is the primitive layer only: ML-DSA-44 signatures, ML-KEM-768 key
//! encapsulation, BIP32 → ML-DSA seed derivation, domain-separated context strings, and
//! signed gossip/DHT message types. There is no ledger, consensus, VM, storage engine, or
//! transport yet — see `docs/16-action-plan.md` for the gated build order.
//!
//! All cryptographic backends are selected at runtime and are architecture-portable; see
//! the backend note in [`crypto::kem`].

// Principle #8 (docs/01-vision/principles.md): memory safety is a security property.
// Unsafe is tolerated only inside vetted upstream cryptographic primitives, never here.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod network;
