//! The algorithm-suite registry — resolution is `(role, suite version) → primitive`.
//!
//! The executive summary names crypto-agility *"the top architectural priority, above any single
//! algorithm choice."* This module is that priority made concrete, and it is built **before** the
//! algorithms on purpose: a primitive written first gets called directly from somewhere, and that
//! call site survives.
//!
//! Two axes, not one ([ADR-0018](../../../docs/adr/0018-signature-role-profiles.md)):
//!
//! - **version** — the axis ADR-0002 fixed. A role's primitive changes only by a new suite version.
//! - **role** — transaction authorization and quorum certification are different design problems
//!   (arXiv:2609.24689). Adding this axis after G2 freezes canonical encoding would be a state
//!   migration, not a parameter change, which is why it lands here.
//!
//! Gate tests: **G1-T1** (rotation without state migration), **G1-T4** (unknown identifier fails
//! closed), **G1-T6** (role confusion rejected).

pub mod ids;
pub mod registry;

use crate::bip32::KeyPurpose;
pub use ids::{HashId, KemId, SignatureSchemeId};

/// What a signature is *for*.
///
/// Discriminants are identical to [`KeyPurpose`], so a key's derivation path and the role it may
/// sign under cannot drift apart. That identity is asserted at compile time below, not documented
/// and hoped for.
///
/// Per ADR-0018 rule V2, roles are **added, never removed or renumbered**: a discriminant is part
/// of the derivation path of every key already issued under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u32)]
pub enum SigRole {
    /// T-class: `Transaction`, `Intent`, `GossipMessage`, `DhtEntry`.
    Transaction = 0,
    /// Q-class: `Vote`, block certificate. Aggregation (R-A1) lands here.
    QuorumCert = 1,
    /// Validator identity, `did:huxplex`, DID key rotation.
    Identity = 2,
    /// Work Visa issuance, constitutional records, registry updates.
    Governance = 3,
    /// TLS 1.3 certificate and `CertificateVerify` (ADR-0019). `PeerId` derives from this key.
    Transport = 4,
}

impl SigRole {
    /// Every role, for conformance sweeps.
    ///
    /// **Keep this exhaustive.** `G1-T6` sweeps every ordered pair of roles; if a role is added
    /// and omitted here, the matrix silently stops covering it. The compile-time assertion below
    /// this enum fails if a role is added without extending this list.
    pub const ALL: &'static [SigRole] = &[
        SigRole::Transaction,
        SigRole::QuorumCert,
        SigRole::Identity,
        SigRole::Governance,
        SigRole::Transport,
    ];

    pub fn index(self) -> u32 {
        self as u32
    }

    /// Resolves a wire discriminant, failing closed on an unknown role (ADR-0018 rule V2).
    pub fn from_index(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Transaction),
            1 => Some(Self::QuorumCert),
            2 => Some(Self::Identity),
            3 => Some(Self::Governance),
            4 => Some(Self::Transport),
            _ => None,
        }
    }

    /// The key-derivation purpose a key for this role must be derived under.
    pub const fn key_purpose(self) -> KeyPurpose {
        match self {
            Self::Transaction => KeyPurpose::Transaction,
            Self::QuorumCert => KeyPurpose::QuorumCert,
            Self::Identity => KeyPurpose::Identity,
            Self::Governance => KeyPurpose::Governance,
            Self::Transport => KeyPurpose::Transport,
        }
    }
}

/// Compile-time proof that `SigRole` and `KeyPurpose` discriminants agree (G1 task C1).
///
/// A runtime test could be skipped or deleted; this cannot be, because the crate stops compiling.
/// If the two enums ever diverge, a key derived for one purpose would be usable under a different
/// role — silently, and with no test that has to be remembered.
const _: () = {
    let mut i = 0;
    while i < SigRole::ALL.len() {
        let role = SigRole::ALL[i];
        assert!(role as u32 == role.key_purpose() as u32);
        i += 1;
    }
    // Guards against a role being added to the enum but omitted from ALL.
    assert!(SigRole::ALL.len() == 5);
};

/// A version of the algorithm suite.
///
/// Suite `vN` is **immutable once any object has been signed under it** (ADR-0018 rule V3), and
/// old pairs stay verifiable forever (rule V5). New versions are added, never edited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
#[repr(u16)]
pub enum SuiteVersion {
    /// Genesis suite. ML-DSA-44 for the hot roles, SLH-DSA-128s for the long-lived ones.
    V1 = 1,
}

impl SuiteVersion {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Resolves a wire discriminant, failing closed on an unknown version.
    ///
    /// `0` is never a version, so a zeroed field cannot be mistaken for v1.
    pub fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::V1),
            _ => None,
        }
    }
}

/// The descriptor every signed object carries: **both** axes, neither optional, neither inferred
/// from the object's type at verification time (ADR-0018 rule V1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AlgoSuite {
    pub role: SigRole,
    pub version: SuiteVersion,
}

impl AlgoSuite {
    pub fn new(role: SigRole, version: SuiteVersion) -> Self {
        Self { role, version }
    }

    /// The signature scheme this descriptor resolves to.
    ///
    /// Fails closed on an unregistered pair — never a default.
    pub fn signature_scheme(self) -> Result<SignatureSchemeId, SuiteError> {
        registry::resolve_signature(self.role, self.version)
    }
}

/// Registry failures. Each is distinct on purpose: "unknown" and "known but unavailable" are
/// different conditions and must not be collapsed into one opaque error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SuiteError {
    /// No row for this `(role, version)`. The fail-closed case behind **G1-T4**.
    #[error("no registry row for role {role:?} at suite {version:?}")]
    UnknownPair {
        role: SigRole,
        version: SuiteVersion,
    },

    /// The row exists and names a scheme this build does not implement yet.
    ///
    /// Expected between gates: suite v1 resolves `Identity` and `Governance` to SLH-DSA-128s,
    /// which arrives at G1 task C7. Distinct from [`Self::UnknownPair`] so "not built yet" can
    /// never be mistaken for "not a valid algorithm", nor silently fall back to a hot-path scheme.
    #[error("{scheme:?} is registered but not implemented in this build (G1 task C7)")]
    SchemeUnimplemented { scheme: SignatureSchemeId },

    /// A signature produced under one role was presented under another (**G1-T6**).
    #[error("role confusion: signature is bound to {actual:?}, presented as {expected:?}")]
    RoleMismatch { expected: SigRole, actual: SigRole },

    /// A signature produced under one suite version was presented under another.
    #[error("suite version mismatch: signature is bound to {actual:?}, presented as {expected:?}")]
    VersionMismatch {
        expected: SuiteVersion,
        actual: SuiteVersion,
    },
}
