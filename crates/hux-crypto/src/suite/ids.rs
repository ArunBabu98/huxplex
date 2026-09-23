//! Stable algorithm identifiers.
//!
//! These discriminants are **wire-visible**: every signed object carries the identifier its
//! signature was produced under, and [ADR-0011](../../../../docs/adr/0011-canonical-serialization.md)
//! makes that encoding canonical at G2. Once an object exists under a discriminant, that number
//! is permanent.
//!
//! Rules, from [crypto spec §1.1](../../../../docs/15-specifications/02-cryptography-spec.md):
//!
//! - identifiers are **added, never removed or renumbered**;
//! - `0` is reserved and never assigned, so a zeroed or default-constructed field is not a
//!   valid identifier — fail-closed by construction rather than by a check someone can forget;
//! - every enum is `#[non_exhaustive]`, so downstream code cannot write a match that silently
//!   becomes wrong when a variant is added.

/// Signature scheme identifiers.
///
/// `Dilithium2` is ML-DSA-44 under its pre-standard name; the crypto spec writes it
/// "ML-DSA-44 (Dilithium2)". The variant keeps the existing name so this gate does not mix a
/// rename into the registry change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u16)]
pub enum SignatureSchemeId {
    /// ML-DSA-44, FIPS 204. Hot path: transactions, votes, transport certificates.
    Dilithium2 = 1,
    /// SLH-DSA-128s, FIPS 205. Long-lived identity and governance.
    ///
    /// **Registered but not yet implemented** — G1 task C7. The registry resolves roles to this
    /// identifier today; asking for an implementation of it returns
    /// [`SuiteError::SchemeUnimplemented`](super::SuiteError::SchemeUnimplemented).
    SlhDsa128s = 2,
}

impl SignatureSchemeId {
    /// The wire discriminant.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Resolves a wire discriminant, failing closed on anything unregistered.
    ///
    /// This is deliberately not `From<u16>`: there is no total mapping, and an unknown
    /// identifier must be an error the caller has to handle, never a default.
    pub fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Dilithium2),
            2 => Some(Self::SlhDsa128s),
            _ => None,
        }
    }

    /// Whether an implementation is available in this build.
    ///
    /// A registered identifier with no implementation is a normal, expected state between
    /// gates — the row exists so the descriptor shape is right, and C7 fills it in.
    pub fn is_implemented(self) -> bool {
        matches!(self, Self::Dilithium2)
    }
}

/// Key-encapsulation mechanism identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u16)]
pub enum KemId {
    /// ML-KEM-768, FIPS 203.
    MlKem768 = 1,
}

impl KemId {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::MlKem768),
            _ => None,
        }
    }
}

/// Hash / XOF identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u16)]
pub enum HashId {
    /// SHAKE-256, FIPS 202. Identity and XOF use (`PeerId`).
    Shake256 = 1,
    /// BLAKE3, 256-bit. Bulk state and Merkle hashing — **not yet implemented**.
    Blake3_256 = 2,
}

impl HashId {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Shake256),
            2 => Some(Self::Blake3_256),
            _ => None,
        }
    }
}
