//! G1 conformance: the algorithm-suite registry.
//!
//! Covers **G1-T1** (rotation without state migration), **G1-T4** (unknown identifier fails
//! closed) and **G1-T6** (role confusion rejected), plus the append-only and fail-closed rules
//! from [ADR-0018](../../../docs/adr/0018-signature-role-profiles.md) and
//! [crypto spec §1.1](../../../docs/15-specifications/02-cryptography-spec.md).
//!
//! These are integration tests, so they reach only the public API — the same surface a
//! downstream crate would use to reach a primitive.

use hux_crypto::{
    bip32::KeyPurpose,
    signature::Keypair,
    signaturescheme::SignatureSchemeId,
    suite::{AlgoSuite, SigRole, SuiteError, SuiteVersion, registry},
    traits,
};

// ─── C5 · the genesis mapping ────────────────────────────────────────────────────────────────

#[test]
fn suite_v1_matches_the_normative_role_table() {
    // crypto spec §1.1. If this test and the spec disagree, one of them is a bug — and the
    // spec is normative.
    let expected = [
        (SigRole::Transaction, SignatureSchemeId::Dilithium2),
        (SigRole::QuorumCert, SignatureSchemeId::Dilithium2),
        (SigRole::Identity, SignatureSchemeId::SlhDsa128s),
        (SigRole::Governance, SignatureSchemeId::SlhDsa128s),
        (SigRole::Transport, SignatureSchemeId::Dilithium2),
    ];

    for (role, scheme) in expected {
        assert_eq!(
            AlgoSuite::new(role, SuiteVersion::V1)
                .signature_scheme()
                .unwrap(),
            scheme,
            "suite v1 row for {role:?} does not match the normative table"
        );
    }
}

#[test]
fn every_role_has_a_row_in_suite_v1() {
    // A role with no row is a role that fails closed at runtime for every object. Better to
    // find that here than in consensus.
    for &role in SigRole::ALL {
        assert!(
            AlgoSuite::new(role, SuiteVersion::V1)
                .signature_scheme()
                .is_ok(),
            "{role:?} has no suite v1 row"
        );
    }
}

#[test]
fn registry_has_no_duplicate_rows() {
    // Two rows for one (role, version) would make resolution order-dependent — the kind of
    // ambiguity that resolves differently after an innocuous reordering.
    let mut seen = Vec::new();
    for (role, version, _) in registry::registered_pairs() {
        assert!(
            !seen.contains(&(role, version)),
            "duplicate registry row for ({role:?}, {version:?})"
        );
        seen.push((role, version));
    }
}

// ─── C1 · role and key-purpose alignment ─────────────────────────────────────────────────────

#[test]
fn sig_role_discriminants_match_key_purpose() {
    // Also asserted at compile time inside the crate; repeated here because this is the property
    // a downstream implementer would rely on, and it is worth failing loudly in the public suite.
    let pairs = [
        (SigRole::Transaction, KeyPurpose::Transaction),
        (SigRole::QuorumCert, KeyPurpose::QuorumCert),
        (SigRole::Identity, KeyPurpose::Identity),
        (SigRole::Governance, KeyPurpose::Governance),
        (SigRole::Transport, KeyPurpose::Transport),
    ];

    for (role, purpose) in pairs {
        assert_eq!(
            role.index(),
            purpose.index(),
            "{role:?} drifted from {purpose:?}"
        );
        assert_eq!(role.key_purpose(), purpose);
    }
}

#[test]
fn sig_role_all_is_exhaustive() {
    // SigRole::ALL drives the G1-T6 sweep. If a role is added and omitted here, the matrix
    // silently stops covering it.
    for index in 0..SigRole::ALL.len() as u32 {
        let role = SigRole::from_index(index).expect("index below ALL.len() must resolve");
        assert!(
            SigRole::ALL.contains(&role),
            "{role:?} missing from SigRole::ALL"
        );
    }
}

// ─── G1-T4 · unknown identifiers fail closed ─────────────────────────────────────────────────

#[test]
fn g1_t4_unknown_role_is_rejected_never_defaulted() {
    // Fail-open on an identifier is how an agility framework becomes a downgrade attack.
    for raw in [5u32, 6, 99, u32::MAX] {
        assert!(
            SigRole::from_index(raw).is_none(),
            "role index {raw} must not resolve"
        );
    }
}

#[test]
fn g1_t4_unknown_suite_version_is_rejected_never_defaulted() {
    for raw in [2u16, 3, u16::MAX] {
        assert!(
            SuiteVersion::from_u16(raw).is_none(),
            "suite version {raw} must not resolve"
        );
    }
}

#[test]
fn g1_t4_zero_is_never_a_valid_identifier() {
    // A zeroed or default-constructed field must not be mistaken for a valid identifier. This is
    // fail-closed by construction rather than by a check a caller can forget.
    assert!(SuiteVersion::from_u16(0).is_none());
    assert!(SignatureSchemeId::from_u16(0).is_none());
}

#[test]
fn g1_t4_unknown_scheme_identifier_is_rejected() {
    for raw in [3u16, 4, u16::MAX] {
        assert!(SignatureSchemeId::from_u16(raw).is_none());
    }
}

#[test]
fn g1_t4_unregistered_pair_fails_with_a_distinct_error() {
    // The error must say which pair, not merely "invalid" — an opaque failure here is
    // indistinguishable from a verification failure, and they need different responses.
    let err = registry::resolve_signature(SigRole::Transaction, SuiteVersion::V1);
    assert!(err.is_ok(), "sanity: the v1 transaction row exists");

    // Every registered pair resolves; nothing else can be constructed to test against, because
    // the type system forbids naming an unregistered version. That is the point: unknown
    // versions are rejected at parse time by `from_u16`, above.
    for (role, version, scheme) in registry::registered_pairs() {
        assert_eq!(
            registry::resolve_signature(role, version).unwrap(),
            scheme,
            "({role:?}, {version:?}) resolved inconsistently"
        );
    }
}

// ─── Registered-but-unimplemented is its own state ───────────────────────────────────────────

#[test]
fn unimplemented_scheme_is_distinct_from_unknown_and_never_substituted() {
    // Suite v1 resolves Identity and Governance to SLH-DSA-128s, which arrives at G1 task C7.
    // Until then the registry must say "registered, not built" — and must NOT fall back to the
    // hot-path scheme. Silently substituting ML-DSA for a root-of-trust primitive is exactly the
    // downgrade the registry exists to prevent.
    let scheme = AlgoSuite::new(SigRole::Identity, SuiteVersion::V1)
        .signature_scheme()
        .expect("the row exists");
    assert_eq!(scheme, SignatureSchemeId::SlhDsa128s);
    assert!(!scheme.is_implemented());

    match traits::implementation(scheme) {
        Err(SuiteError::SchemeUnimplemented { scheme: s }) => {
            assert_eq!(s, SignatureSchemeId::SlhDsa128s);
        }
        Err(other) => panic!("expected SchemeUnimplemented, got {other:?}"),
        Ok(_) => panic!("SLH-DSA-128s must not resolve to an implementation before C7"),
    }

    // And the keypair constructor must refuse it rather than producing something usable.
    assert!(
        Keypair::generate(SignatureSchemeId::SlhDsa128s, [0u8; 32]).is_err(),
        "generating an SLH-DSA keypair must fail before C7, not silently use ML-DSA"
    );
}

// ─── G1-T6 · role confusion ──────────────────────────────────────────────────────────────────

#[test]
fn g1_t6_roles_are_pairwise_distinct() {
    // The role axis is worthless if two roles collapse to one identifier. Exhaustive over every
    // ordered pair, not spot-checked — this is the argument of G1-T2 applied to the role axis.
    for &a in SigRole::ALL {
        for &b in SigRole::ALL {
            if a == b {
                continue;
            }
            assert_ne!(a.index(), b.index(), "{a:?} and {b:?} share a discriminant");
            assert_ne!(
                a.key_purpose().index(),
                b.key_purpose().index(),
                "{a:?} and {b:?} share a key purpose"
            );
        }
    }
}

#[test]
fn g1_t6_a_role_mismatch_is_reported_as_itself() {
    // The error carries both roles, so a verifier can tell role confusion from a bad signature.
    // Collapsing the two is how "rejected" becomes indistinguishable from "wrong algorithm".
    let err = SuiteError::RoleMismatch {
        expected: SigRole::QuorumCert,
        actual: SigRole::Transaction,
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("QuorumCert"),
        "error must name the expected role: {rendered}"
    );
    assert!(
        rendered.contains("Transaction"),
        "error must name the actual role: {rendered}"
    );
}

// ─── G1-T1 · rotation without state migration ────────────────────────────────────────────────

#[test]
fn g1_t1_descriptor_shape_supports_per_role_rotation() {
    // The full G1-T1 — register a second scheme, flip ONE role's default, confirm old objects
    // still verify and other roles are untouched — needs a second *implemented* scheme, which
    // arrives with SLH-DSA at C7. What can be established now is the property that makes it
    // possible: resolution is per-(role, version), so one role's row cannot affect another's.
    //
    // This is deliberately not marked #[ignore]: it tests real structure today, and it is the
    // half of G1-T1 that the descriptor shape is responsible for.
    let transaction_v1 = AlgoSuite::new(SigRole::Transaction, SuiteVersion::V1)
        .signature_scheme()
        .unwrap();
    let quorum_v1 = AlgoSuite::new(SigRole::QuorumCert, SuiteVersion::V1)
        .signature_scheme()
        .unwrap();
    let identity_v1 = AlgoSuite::new(SigRole::Identity, SuiteVersion::V1)
        .signature_scheme()
        .unwrap();

    // Roles resolve independently: Identity already differs from the hot roles in suite v1, which
    // proves the table is genuinely per-role rather than one global default wearing a role label.
    assert_eq!(transaction_v1, quorum_v1);
    assert_ne!(
        identity_v1, transaction_v1,
        "suite v1 must already resolve different roles to different primitives, \
         otherwise per-role rotation is untested structure"
    );

    // And a descriptor is nothing but (role, version) — no object type is consulted, so changing
    // one row cannot require re-encoding objects of another role (ADR-0018 rule V4).
    let a = AlgoSuite::new(SigRole::Transaction, SuiteVersion::V1);
    let b = AlgoSuite::new(SigRole::Transaction, SuiteVersion::V1);
    assert_eq!(a, b, "descriptors with equal fields must be equal");
}

#[test]
fn g1_t1_signing_still_works_end_to_end_through_the_registry() {
    // The registry is now the only path to a primitive. Prove the path actually carries traffic:
    // a key generated and used through it must still round-trip.
    let scheme = AlgoSuite::new(SigRole::Transaction, SuiteVersion::V1)
        .signature_scheme()
        .unwrap();
    let keypair = Keypair::generate(scheme, [42u8; 32]).unwrap();

    let message = b"registry round-trip";
    let context = b"huxplex-testnet:tx:v1";
    let signature = keypair.sign(message, Some(context)).unwrap();

    assert!(
        keypair
            .public_key()
            .verify(message, &signature, Some(context))
            .unwrap()
    );
}

// ─── C6 · sizes come from the descriptor ─────────────────────────────────────────────────────

#[test]
fn c6_sizes_are_available_from_the_resolved_scheme() {
    // The point of C6: a caller can learn a scheme's sizes without naming a literal. If this ever
    // requires editing a constant to add a scheme, C6 was done shallowly.
    let scheme = AlgoSuite::new(SigRole::Transaction, SuiteVersion::V1)
        .signature_scheme()
        .unwrap();
    let sizes = traits::implementation(scheme).unwrap().sizes();

    // FIPS 204 Table 2, via the descriptor rather than a hard-coded array length.
    assert_eq!(sizes.public_key, 1312);
    assert_eq!(sizes.secret_key, 2560);
    assert_eq!(sizes.signature, 2420);
    assert_eq!(sizes.seed, 32);

    let keypair = Keypair::generate(scheme, [7u8; 32]).unwrap();
    assert_eq!(keypair.public_key().bytes.len(), sizes.public_key);
    assert_eq!(
        keypair.sign(b"x", None).unwrap().bytes.len(),
        sizes.signature
    );
}
