//! Huxplex Layer 0 — networking.
//!
//! Today this crate provides peer identity (`PeerId = SHAKE-256(ml_dsa44_pk)[..32]`) and the
//! signed gossip and DHT envelopes. The transport itself — libp2p/QUIC with native ML-DSA TLS
//! certificates — arrives at gate **G5**; see `docs/18-implementation-plan/03-g5-transport.md`.

pub mod error;
pub mod message;
pub mod peer;
pub mod topic;
