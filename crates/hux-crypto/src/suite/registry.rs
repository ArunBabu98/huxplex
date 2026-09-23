//! The append-only `(role, suite version) → primitive` table.
//!
//! This is deliberately **dumb**: a lookup plus a dispatch, not a policy engine. Where the table
//! eventually lives on-chain (genesis config vs. an HRM system resource) is a G3 question owned
//! by `docs/03-post-quantum/crypto-agility.md`. At G1 it is static, behind a trait, with a seam
//! for a state-backed source later. Building the governance path now would be scaffolding for a
//! state model that does not exist.
//!
//! Normative source: [crypto spec §1.1](../../../../docs/15-specifications/02-cryptography-spec.md),
//! decided in [ADR-0018](../../../../docs/adr/0018-signature-role-profiles.md).

use super::{SigRole, SuiteError, SuiteVersion, ids::SignatureSchemeId};

/// One row of the signature table.
struct Row {
    role: SigRole,
    version: SuiteVersion,
    scheme: SignatureSchemeId,
}

/// **Suite v1 — the genesis mapping.**
///
/// Every role resolves to the primitive ADR-0002 already chose, so nothing about v1's bytes on
/// the wire changes except the descriptor itself (ADR-0018 §2).
///
/// | Role | Suite v1 | Why |
/// |---|---|---|
/// | `Transaction` | ML-DSA-44 | unchanged; matches the frozen v1 scope |
/// | `QuorumCert` | ML-DSA-44 | unchanged; the aggregation answer (R-A1) lands here later |
/// | `Identity` | SLH-DSA-128s | long-lived root of trust |
/// | `Governance` | SLH-DSA-128s | same longevity argument as `Identity` |
/// | `Transport` | ML-DSA-44 | TLS certificate key, `SignatureScheme` 0x0904 (ADR-0019) |
///
/// **This table is append-only.** Rule V3: a committed row is immutable once any object has
/// been signed under it; a role's primitive changes only by introducing a new suite version.
/// Editing a row below is a consensus-breaking change and is forbidden.
const SIGNATURE_TABLE: &[Row] = &[
    Row {
        role: SigRole::Transaction,
        version: SuiteVersion::V1,
        scheme: SignatureSchemeId::Dilithium2,
    },
    Row {
        role: SigRole::QuorumCert,
        version: SuiteVersion::V1,
        scheme: SignatureSchemeId::Dilithium2,
    },
    Row {
        role: SigRole::Identity,
        version: SuiteVersion::V1,
        scheme: SignatureSchemeId::SlhDsa128s,
    },
    Row {
        role: SigRole::Governance,
        version: SuiteVersion::V1,
        scheme: SignatureSchemeId::SlhDsa128s,
    },
    Row {
        role: SigRole::Transport,
        version: SuiteVersion::V1,
        scheme: SignatureSchemeId::Dilithium2,
    },
];

/// Resolves `(role, version)` to its signature scheme.
///
/// Fails closed: an unregistered pair is [`SuiteError::UnknownPair`], never a default. Fail-open
/// on an algorithm identifier is how an agility framework becomes a downgrade attack — the
/// property pinned by **G1-T4**.
pub fn resolve_signature(
    role: SigRole,
    version: SuiteVersion,
) -> Result<SignatureSchemeId, SuiteError> {
    SIGNATURE_TABLE
        .iter()
        .find(|row| row.role == role && row.version == version)
        .map(|row| row.scheme)
        .ok_or(SuiteError::UnknownPair { role, version })
}

/// Every `(role, version)` pair the registry knows, in table order.
///
/// Exists so conformance tests can sweep the registry rather than restate it — a hand-written
/// list in a test drifts from the table it is meant to check.
pub fn registered_pairs() -> impl Iterator<Item = (SigRole, SuiteVersion, SignatureSchemeId)> {
    SIGNATURE_TABLE
        .iter()
        .map(|row| (row.role, row.version, row.scheme))
}
