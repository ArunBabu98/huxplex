//! Huxplex Layer 0 — networking.
//!
//! Peer identity (`PeerId = SHAKE-256(ml_dsa44_pk)[..32]`), the signed gossip and DHT envelopes
//! under the canonical codec (G2a), and the transport (G5): QUIC with native ML-DSA-44 TLS
//! certificates behind libp2p, GossipSub and Kademlia. See
//! `docs/18-implementation-plan/03-g5-transport.md`.

pub mod error;
pub mod message;
pub mod node;
pub mod peer;
pub mod peers;
pub mod topic;
pub mod transport;
