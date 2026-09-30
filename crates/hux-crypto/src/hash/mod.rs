//! Hash and XOF primitives.
//!
//! `shake` is implemented; BLAKE3 (bulk state and Merkle hashing,
//! [ADR-0010](../../../../docs/adr/0010-hash-function-domains.md)) arrives with the consensus
//! types at G2b, and gains a `Hasher` trait at the same time — a trait written against one
//! implementation encodes that implementation's shape.

pub mod shake;
