//! The canonical codec — [ADR-0011](../../../docs/adr/0011-canonical-serialization.md),
//! [data-model spec §1](../../../docs/15-specifications/01-data-model-and-encoding.md).
//!
//! **This module is the only place in the workspace permitted to name `postcard`** (enforced by
//! `scripts/check-primitive-encapsulation.sh`). Every hashed, signed or gossiped object is encoded
//! through [`Codec`], so the library underneath can be replaced under agility without touching a
//! call site — and so there is exactly **one** encoder. [ADR-0022](../../../docs/adr/0022-g2-split-wire-and-consensus-encoding.md)
//! splits G2 into wire (G2a) and consensus (G2b) types; both halves encode through this module.
//! A second encoder would be a second dialect, which is the fork risk the gate exists to prevent.
//!
//! # The canonical-decode rule
//!
//! [`from_canonical`] decodes, **re-encodes, and rejects the input unless the bytes match
//! exactly.** That one comparison is what makes the encoding non-malleable regardless of what the
//! underlying library tolerates: overlong varints, trailing bytes, and any other alternate spelling
//! of a value all fail it. It is the property **G2-T1** and **G2-T2** test, and the reason
//! distinct byte strings can never decode to the same value (**G2-T4**): if `decode(a) = decode(b)
//! = v`, then `a = encode(v) = b`.

use serde::{Serialize, de::DeserializeOwned};

/// Canonical encode / decode for a top-level object.
///
/// `decode` MUST be canonical — implementations go through [`from_canonical`], never around it.
pub trait Codec: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Result<Self, CodecError>;
}

/// Why bytes were refused. Each case is distinct: a malformed input, a well-formed but
/// non-canonical one, and an oversized one call for different responses (and, at G5, different
/// peer-scoring penalties).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Not a valid encoding of the type: truncated, an invalid tag, an unregistered identifier,
    /// a field of the wrong size.
    #[error("malformed encoding: {0}")]
    Malformed(String),

    /// Decodes, but is not the canonical encoding of what it decodes to. Rejected rather than
    /// normalised (ADR-0011 rule 2): accepting it would give one value two byte strings.
    #[error("non-canonical encoding")]
    NonCanonical,

    /// Larger than the type's bound — checked before any decoding work is done.
    #[error("encoding is {actual} bytes; the limit is {max}")]
    TooLarge { max: usize, actual: usize },
}

/// Encodes a serde-shaped wire form. Infallible for the types this workspace defines: none has a
/// field postcard cannot represent, and there is no I/O.
pub fn to_canonical<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("wire forms contain only postcard-encodable fields")
}

/// Decodes a serde-shaped wire form **canonically**: bound-check, decode, re-encode, compare.
pub fn from_canonical<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    max_len: usize,
) -> Result<T, CodecError> {
    if bytes.len() > max_len {
        return Err(CodecError::TooLarge {
            max: max_len,
            actual: bytes.len(),
        });
    }
    let value: T = postcard::from_bytes(bytes).map_err(|e| CodecError::Malformed(e.to_string()))?;
    if to_canonical(&value) != bytes {
        return Err(CodecError::NonCanonical);
    }
    Ok(value)
}
