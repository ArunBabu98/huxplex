//! Signature scheme identifiers.
//!
//! The canonical definition moved to [`crate::suite::ids`] with the G1 registry, because the
//! identifier is one half of the `(role, version)` descriptor and belongs beside it. This
//! re-export keeps `hux_crypto::signaturescheme::SignatureSchemeId` working for existing
//! callers.

pub use crate::suite::ids::SignatureSchemeId;
