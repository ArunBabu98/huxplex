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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    resolve_in(SIGNATURE_TABLE, role, version)
}

/// Resolution over a given table. The production table is [`SIGNATURE_TABLE`]; this is the seam
/// a state-backed source plugs into at G3, and what G1-T1 drives with a rotated table.
fn resolve_in(
    table: &[Row],
    role: SigRole,
    version: SuiteVersion,
) -> Result<SignatureSchemeId, SuiteError> {
    table
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

#[cfg(test)]
mod g1_t1_rotation {
    //! **G1-T1 — algorithm rotation without state migration.** *Register a second scheme, flip one
    //! role's default; old objects still verify, other roles untouched, zero state-structure
    //! changes.*
    //!
    //! The second scheme is SLH-DSA-128s (G1 task C7). The flip is a suite-v2 table that keeps
    //! every v1 row and appends one: `QuorumCert` moves to SLH-DSA. Nothing else changes — not
    //! the signed object's type, not any other role's row, not the signatures already made.

    use super::*;
    use crate::{
        error::{CryptoError, CryptoResult},
        publickey::PublicKey,
        signature::{Keypair, Signature},
        suite::AlgoSuite,
        traits,
    };

    /// A signed object as the chain would store it: descriptor, signer, signature. **The same
    /// type before and after the rotation** — that is the "zero state-structure changes" half.
    struct SignedObject {
        suite: AlgoSuite,
        signer: PublicKey,
        sig: Signature,
    }

    /// Verification that consults only the object's own descriptor and the table (rule V1).
    fn verify(table: &[Row], obj: &SignedObject, msg: &[u8], ctx: &[u8]) -> CryptoResult<bool> {
        let scheme = resolve_in(table, obj.suite.role, obj.suite.version)?;
        if obj.sig.scheme != scheme {
            return Err(CryptoError::SchemeMismatch {
                expected: scheme,
                actual: obj.sig.scheme,
            });
        }
        obj.signer.verify(msg, &obj.sig, Some(ctx))
    }

    fn sign(table: &[Row], suite: AlgoSuite, seed: &[u8], msg: &[u8], ctx: &[u8]) -> SignedObject {
        let scheme = resolve_in(table, suite.role, suite.version).unwrap();
        // Seed length comes from the resolved scheme (task C6), so this helper is scheme-blind.
        let seed = &seed[..traits::implementation(scheme).unwrap().sizes().seed];
        let kp = Keypair::generate_from_seed(scheme, seed).unwrap();
        SignedObject {
            suite,
            signer: kp.public_key().clone(),
            sig: kp.sign(msg, Some(ctx)).unwrap(),
        }
    }

    fn rotated_table() -> Vec<Row> {
        let mut table = SIGNATURE_TABLE.to_vec();
        table.push(Row {
            role: SigRole::QuorumCert,
            version: SuiteVersion::V2,
            scheme: SignatureSchemeId::SlhDsa128s,
        });
        table
    }

    const CTX: &[u8] = b"huxplex-testnet:block:commit:v1";
    const SEED: [u8; 48] = [0x42; 48];

    #[test]
    fn g1_t1_rotation_is_append_only() {
        let v2 = rotated_table();
        assert_eq!(
            &v2[..SIGNATURE_TABLE.len()],
            SIGNATURE_TABLE,
            "v1 rows must be untouched"
        );
        assert_eq!(
            v2.len(),
            SIGNATURE_TABLE.len() + 1,
            "exactly one row appended"
        );
    }

    #[test]
    fn g1_t1_old_objects_still_verify_after_rotation() {
        let v1_suite = AlgoSuite::new(SigRole::QuorumCert, SuiteVersion::V1);
        let vote = sign(SIGNATURE_TABLE, v1_suite, &SEED, b"block 7", CTX);
        assert_eq!(vote.sig.scheme, SignatureSchemeId::Dilithium2);

        // Rule V5: the old pair stays verifiable under the new table, untouched.
        assert!(verify(&rotated_table(), &vote, b"block 7", CTX).unwrap());
    }

    #[test]
    fn g1_t1_the_flipped_role_signs_under_the_new_scheme() {
        let v2 = rotated_table();
        let v2_suite = AlgoSuite::new(SigRole::QuorumCert, SuiteVersion::V2);
        let vote = sign(&v2, v2_suite, &SEED, b"block 8", CTX);

        assert_eq!(vote.sig.scheme, SignatureSchemeId::SlhDsa128s);
        assert!(verify(&v2, &vote, b"block 8", CTX).unwrap());
    }

    #[test]
    fn g1_t1_other_roles_are_untouched() {
        // Roles version independently (crypto spec §1.1 rule 3): every other role resolves exactly
        // as before at v1, and has no v2 row at all — rotating QuorumCert rotated nothing else.
        let v2 = rotated_table();
        for &role in SigRole::ALL {
            assert_eq!(
                resolve_in(&v2, role, SuiteVersion::V1),
                resolve_in(SIGNATURE_TABLE, role, SuiteVersion::V1),
                "{role:?} changed at v1"
            );
            if role != SigRole::QuorumCert {
                assert_eq!(
                    resolve_in(&v2, role, SuiteVersion::V2),
                    Err(SuiteError::UnknownPair {
                        role,
                        version: SuiteVersion::V2
                    }),
                    "{role:?} was rotated along with QuorumCert"
                );
            }
        }
    }

    #[test]
    fn g1_t1_a_relabelled_descriptor_is_refused() {
        // An old ML-DSA vote whose descriptor is rewritten to claim v2 must not verify: v2 says
        // SLH-DSA, the signature says ML-DSA, and the mismatch is reported as itself.
        let v2 = rotated_table();
        let mut vote = sign(
            SIGNATURE_TABLE,
            AlgoSuite::new(SigRole::QuorumCert, SuiteVersion::V1),
            &SEED,
            b"block 7",
            CTX,
        );
        vote.suite.version = SuiteVersion::V2;
        assert!(matches!(
            verify(&v2, &vote, b"block 7", CTX),
            Err(CryptoError::SchemeMismatch { .. })
        ));
    }
}
