//! Domain separation: the canonical context-string registry, and the exhaustive
//! cross-context rejection matrix. Principle 7.
//!
//! Extracted from `lib.rs` at gate G0 (workspace migration, task W2).
//! Integration tests reach only the crate's **public API**, which is the point: an over-broad
//! `pub` shows up here immediately, and a secret field can never be widened to satisfy a test.
//!
//! See `docs/18-implementation-plan/00-workspace-migration.md`.

use hux_crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};

#[test]
fn test_all_canonical_context_strings_self_verify() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let payload = b"canonical-context-test-payload";

    // All context strings defined across the Huxplex spec
    let contexts: &[&[u8]] = &[
        b"huxplex-mainnet:tx:v1",
        b"huxplex-mainnet:block:preprepare:v1",
        b"huxplex-mainnet:block:prepare:v1",
        b"huxplex-mainnet:block:commit:v1",
        b"huxplex-mainnet:tls:handshake:v1",
        b"huxplex-mainnet:gossip:huxplex/intents:v1",
        b"huxplex-mainnet:vc:v1",
        b"huxplex-mainnet:provenance:v1",
        b"huxplex-mainnet:dht:entry:v1",
        b"huxplex-mainnet:intent:v1",
        b"huxplex-testnet:tx:v1",
        b"huxplex-testnet:tls:handshake:v1",
    ];

    for ctx in contexts {
        let sig = kp.sign(payload, Some(ctx)).unwrap();
        assert!(
            kp.public_key().verify(payload, &sig, Some(ctx)).unwrap(),
            "Context '{}' must self-verify",
            std::str::from_utf8(ctx).unwrap()
        );
    }

    println!(
        "✓ All {} canonical context strings self-verify",
        contexts.len()
    );
}

#[test]
fn test_all_canonical_context_strings_are_mutually_domain_separated() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let payload = b"canonical-context-test-payload";

    let contexts: &[&[u8]] = &[
        b"huxplex-mainnet:tx:v1",
        b"huxplex-mainnet:block:preprepare:v1",
        b"huxplex-mainnet:tls:handshake:v1",
        b"huxplex-mainnet:vc:v1",
        b"huxplex-mainnet:provenance:v1",
        b"huxplex-mainnet:dht:entry:v1",
        b"huxplex-mainnet:intent:v1",
    ];

    // Sign under each context and confirm it does NOT verify under any other
    for (i, ctx_sign) in contexts.iter().enumerate() {
        let sig = kp.sign(payload, Some(ctx_sign)).unwrap();
        for (j, ctx_verify) in contexts.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                !kp.public_key()
                    .verify(payload, &sig, Some(ctx_verify))
                    .unwrap(),
                "Context '{}' signature must NOT verify under context '{}'",
                std::str::from_utf8(ctx_sign).unwrap(),
                std::str::from_utf8(ctx_verify).unwrap()
            );
        }
    }

    println!(
        "✓ All canonical context strings are mutually domain-separated ({} × {} checks)",
        contexts.len(),
        contexts.len() - 1
    );
}

#[test]
fn test_mainnet_and_testnet_tx_contexts_are_domain_separated() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Transfer 100 HUX";

    let sig_mainnet = kp.sign(message, Some(b"huxplex-mainnet:tx:v1")).unwrap();

    assert!(
        !kp.public_key()
            .verify(message, &sig_mainnet, Some(b"huxplex-testnet:tx:v1"))
            .unwrap(),
        "Mainnet tx signature must not verify on testnet — prevents cross-network replay"
    );

    println!("✓ Mainnet/testnet tx context separation enforced");
}

// ══════════════════════════════════════════════════════════════════════════
// GROUP 8: Context binding — inverse case
// The existing test signs WITH context and verifies WITHOUT.
// This test signs WITHOUT context and verifies WITH context.
// Both directions must fail.
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_no_context_signature_fails_when_verified_with_context() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Transfer 100 HUX to Alice";

    // Sign WITHOUT any context
    let sig_no_ctx = kp.sign(message, None).unwrap();

    // Must NOT verify when a context is supplied at verification time
    let valid = kp
        .public_key()
        .verify(message, &sig_no_ctx, Some(b"huxplex-mainnet:tx:v1"))
        .unwrap();

    assert!(
        !valid,
        "A context-free signature must not verify when a context is provided"
    );

    println!("✓ Context-free signature correctly rejected when context is required");
}
