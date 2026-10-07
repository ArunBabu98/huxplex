//! Huxplex — canonical encoding and the core types' wire forms.
//!
//! [`codec`] is the single canonical `Codec` for every hashed, signed or gossiped object
//! ([ADR-0011](../../../docs/adr/0011-canonical-serialization.md)). [`wire`] gives the
//! `hux-crypto` types their frozen on-the-wire shape.
//!
//! Gate **G2a** ([ADR-0022](../../../docs/adr/0022-g2-split-wire-and-consensus-encoding.md))
//! brings the wire envelopes (`GossipMessage`, `DhtEntry`, in `hux-network`) under the codec.
//! The consensus types — `Resource`, `Transaction`, `Block`, `Vote` — join this crate at **G2b**,
//! through the same codec.

pub mod codec;
pub mod wire;
