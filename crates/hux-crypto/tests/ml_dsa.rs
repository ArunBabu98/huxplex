//! ML-DSA-44 (FIPS 204) conformance: key generation, signing, verification,
//! tamper rejection, hedged-signing behaviour and secret hygiene.
//!
//! Extracted from `lib.rs` at gate G0 (workspace migration, task W2).
//! Integration tests reach only the crate's **public API**, which is the point: an over-broad
//! `pub` shows up here immediately, and a secret field can never be widened to satisfy a test.
//!
//! See `docs/18-implementation-plan/00-workspace-migration.md`.

use hux_crypto::{
    bip32::derive_mldsa_seed, privatekey::PrivateKey, signature::Keypair,
    signaturescheme::SignatureSchemeId,
};

const HEXSEED: &str = "75ca70e0863b97e3e5cde1bc9b6eae8101158802cf7e916e7afc03f241941996dd0d391e42f36345af6079f35003270390a4a958492b5f9563fa629e89262177";

#[test]
fn test_keypair_generation_creates_valid_keys() {
    let bytes = hex::decode(HEXSEED).expect("Must be valid hex");
    let seed = derive_mldsa_seed(
        bytes.as_slice().try_into().expect("Seed must be 64 bytes"),
        0,
    );
    // Research Question: Are keys deterministic from same randomness?
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, seed)
        .expect("Keypair generation should succeed");

    // Dilithium2 constants (from pqcrypto spec)
    assert_eq!(keypair.public_key().bytes.len(), 1312); // PUBLIC_KEY_BYTES
    assert_eq!(keypair.private_key().len(), 2560); // SECRET_KEY_BYTES - updated
    assert_eq!(keypair.public_key().scheme, SignatureSchemeId::Dilithium2);
}

#[test]
fn test_deterministic_generation_same_seed_same_keys() {
    // Research: Can we reproduce same keys from seed?
    let bytes = hex::decode(HEXSEED).expect("Must be valid hex");
    let seed = derive_mldsa_seed(
        bytes.as_slice().try_into().expect("Seed must be 64 bytes"),
        0,
    );

    let keypair1 =
        Keypair::generate(SignatureSchemeId::Dilithium2, seed).expect("Generation should succeed");
    let keypair2 =
        Keypair::generate(SignatureSchemeId::Dilithium2, seed).expect("Generation should succeed");

    assert_eq!(
        keypair1.public_key().bytes,
        keypair2.public_key().bytes,
        "Same seed must produce identical public keys"
    );
    assert_eq!(
        keypair1.private_key().expose_secret(),
        keypair2.private_key().expose_secret(),
        "Same seed must produce identical private keys"
    );
}
#[test]
fn test_sign_and_verify_roundtrip() {
    let seed = [99u8; 32];
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap();
    let message = b"Transfer 100 HUX to Alice";

    let signature = keypair.sign(message, None).unwrap();
    let is_valid = keypair
        .public_key()
        .verify(message, &signature, None)
        .unwrap();
    println!("{}", is_valid);
    assert!(is_valid);
    assert_eq!(signature.bytes.len(), 2420);
}

#[test]
fn test_tampered_message_fails() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();

    let original = b"Transfer 100 HUX to Alice";
    let tampered = b"Transfer 999 HUX to Alice";

    let signature = keypair.sign(original, None).unwrap();
    let is_valid = keypair
        .public_key()
        .verify(tampered, &signature, None)
        .unwrap();
    println!("{}", is_valid);
    assert!(!is_valid, "Tampered message should fail verification");
}
#[test]
fn test_wrong_public_key_fails_verification() {
    let keypair1 = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let keypair2 = Keypair::generate(SignatureSchemeId::Dilithium2, [2u8; 32]).unwrap();

    let message = b"Causal clock: {n1:5, n2:3}";
    let signature = keypair1.sign(message, None).unwrap();

    // Verify with correct key succeeds
    let is_valid_correct = keypair1
        .public_key()
        .verify(message, &signature, None)
        .unwrap();
    assert!(is_valid_correct, "Correct key should verify");

    // Verify with wrong key fails
    let is_valid_wrong = keypair2
        .public_key()
        .verify(message, &signature, None)
        .unwrap();
    assert!(!is_valid_wrong, "Wrong key should fail verification");

    println!("✓ Wrong key detection working");
}

#[test]
fn test_signature_overhead() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let signature = keypair.sign(b"test", None).unwrap();

    assert_eq!(signature.bytes.len(), 2420);

    // Research metric
    let ed25519_size = 64;
    let overhead_ratio = signature.bytes.len() / ed25519_size;

    println!("=== Post-Quantum Signature Overhead ===");
    println!("ML-DSA-44 signature: {} bytes", signature.bytes.len());
    println!("Ed25519 equivalent: {} bytes", ed25519_size);
    println!("Overhead ratio: {}x", overhead_ratio);
    println!(
        "Additional cost: {} bytes per signature",
        signature.bytes.len() - ed25519_size
    );
}

#[test]
fn test_context_binding() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Transfer 100 HUX to Alice";

    // Sign with mainnet context
    let mainnet_ctx = b"huxplex-mainnet:tx:v1";
    let sig_mainnet = keypair.sign(message, Some(mainnet_ctx)).unwrap();

    // Verify with correct context succeeds
    let is_valid_correct = keypair
        .public_key()
        .verify(message, &sig_mainnet, Some(mainnet_ctx))
        .unwrap();
    assert!(is_valid_correct, "Correct context should verify");

    // Verify with wrong context fails
    let testnet_ctx = b"huxplex-testnet:tx:v1";
    let is_valid_wrong = keypair
        .public_key()
        .verify(message, &sig_mainnet, Some(testnet_ctx))
        .unwrap();
    assert!(!is_valid_wrong, "Wrong context should fail verification");

    // Verify with no context fails
    let is_valid_none = keypair
        .public_key()
        .verify(message, &sig_mainnet, None)
        .unwrap();
    assert!(!is_valid_none, "Missing context should fail verification");

    println!("✓ Context binding prevents cross-domain replay");
}

#[test]
fn test_different_seeds_different_keys() {
    let kp1 = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let kp2 = Keypair::generate(SignatureSchemeId::Dilithium2, [2u8; 32]).unwrap();

    assert_ne!(kp1.public_key().bytes, kp2.public_key().bytes);
    assert_ne!(
        kp1.private_key().expose_secret(),
        kp2.private_key().expose_secret()
    );

    println!("✓ Different seeds produce different keys");
}

#[test]
fn test_empty_message_signing() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let empty_message = b"";

    let signature = keypair.sign(empty_message, None).unwrap();
    let is_valid = keypair
        .public_key()
        .verify(empty_message, &signature, None)
        .unwrap();

    assert!(is_valid, "Empty message should be signable and verifiable");

    println!("✓ Empty message handling works");
}

#[test]
fn test_large_message_signing() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();

    // 1 MB message
    let large_message = vec![0xAB; 1024 * 1024];

    let signature = keypair.sign(&large_message, None).unwrap();
    let is_valid = keypair
        .public_key()
        .verify(&large_message, &signature, None)
        .unwrap();

    assert!(is_valid, "Large message should be signable");

    println!("✓ Large message (1MB) handling works");
}
// ══════════════════════════════════════════════════════════════════════════
// GROUP 2: Randomized signing property
// ML-DSA (FIPS 204) uses randomized signing — two calls on the same
// (message, key) pair produce DIFFERENT bytes, but BOTH must verify.
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_randomized_signing_produces_different_bytes_both_valid() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Transfer 100 HUX to Alice";

    let sig1 = keypair.sign(message, None).unwrap();
    let sig2 = keypair.sign(message, None).unwrap();

    // ML-DSA randomized signing: signature bytes differ between calls
    assert_ne!(
        sig1.bytes, sig2.bytes,
        "ML-DSA randomized signing must produce different signature bytes on each call"
    );

    // Both must still verify correctly
    assert!(
        keypair.public_key().verify(message, &sig1, None).unwrap(),
        "First randomized signature must verify"
    );
    assert!(
        keypair.public_key().verify(message, &sig2, None).unwrap(),
        "Second randomized signature must verify"
    );

    println!("✓ ML-DSA randomized signing: two sigs differ but both verify");
}

#[test]
fn test_randomized_signing_with_context_both_sigs_differ_and_verify() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"block-hash:0xdeadbeef";
    let ctx = b"huxplex-mainnet:block:preprepare:v1";

    let sig1 = keypair.sign(message, Some(ctx)).unwrap();
    let sig2 = keypair.sign(message, Some(ctx)).unwrap();

    assert_ne!(
        sig1.bytes, sig2.bytes,
        "Context-bound sigs must also be non-deterministic"
    );

    assert!(
        keypair
            .public_key()
            .verify(message, &sig1, Some(ctx))
            .unwrap()
    );
    assert!(
        keypair
            .public_key()
            .verify(message, &sig2, Some(ctx))
            .unwrap()
    );
}

// ══════════════════════════════════════════════════════════════════════════
// GROUP 3: Signature byte manipulation
// Current tests tamper the message. These tamper the SIGNATURE BYTES.
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_first_byte_flip_in_signature_fails_verification() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Transfer 100 HUX to Alice";
    let sig = keypair.sign(message, None).unwrap();

    let mut tampered = sig.clone();
    tampered.bytes[0] ^= 0x01;

    assert!(
        !keypair
            .public_key()
            .verify(message, &tampered, None)
            .unwrap(),
        "First-byte flip in signature must fail verification"
    );
}

#[test]
fn test_last_byte_flip_in_signature_fails_verification() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Validator commit vote";
    let sig = keypair.sign(message, None).unwrap();

    let mut tampered = sig.clone();
    tampered.bytes[2419] ^= 0xFF; // last byte of a 2420-byte ML-DSA-44 signature

    assert!(
        !keypair
            .public_key()
            .verify(message, &tampered, None)
            .unwrap(),
        "Last-byte flip in signature must fail verification"
    );
}

#[test]
fn test_middle_byte_flip_in_signature_fails_verification() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Intent: swap 10 HUX for 5 SNTNC";
    let sig = keypair.sign(message, None).unwrap();

    let mut tampered = sig.clone();
    tampered.bytes[1210] ^= 0xAA; // middle of the 2420-byte signature

    assert!(
        !keypair
            .public_key()
            .verify(message, &tampered, None)
            .unwrap(),
        "Middle-byte flip in signature must fail verification"
    );
}

#[test]
fn test_all_zero_signature_fails_verification() {
    let keypair = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let message = b"Transfer 100 HUX";
    let sig = keypair.sign(message, None).unwrap();

    let mut zeroed = sig.clone();
    zeroed.bytes = vec![0u8; 2420];

    assert!(
        !keypair.public_key().verify(message, &zeroed, None).unwrap(),
        "All-zero signature must fail verification"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// GROUP 4: Key and signature non-triviality
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_public_key_bytes_are_non_trivial() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    assert_ne!(
        kp.public_key().bytes,
        vec![0u8; 1312],
        "ML-DSA-44 public key must not be all-zero"
    );
    assert_ne!(
        kp.public_key().bytes,
        vec![0xFFu8; 1312],
        "ML-DSA-44 public key must not be all-0xFF"
    );
}

#[test]
fn test_private_key_bytes_are_non_trivial() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    assert_ne!(
        kp.private_key().expose_secret(),
        vec![0u8; 2560],
        "ML-DSA-44 secret key must not be all-zero"
    );
    assert_ne!(
        kp.private_key().expose_secret(),
        vec![0xFFu8; 2560],
        "ML-DSA-44 secret key must not be all-0xFF"
    );
}

#[test]
fn test_private_key_debug_never_leaks_secret_bytes() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [7u8; 32]).unwrap();
    let sk = kp.private_key();
    let secret = sk.expose_secret();

    // Both the compact and the pretty formatter, because they are separate code paths.
    for rendered in [format!("{sk:?}"), format!("{sk:#?}")] {
        assert!(
            rendered.contains("redacted"),
            "Debug output must announce that the key is redacted, got: {rendered}"
        );

        // 1. No hex rendering of any 8-byte window of the key.
        let hex_all = hex::encode(secret);
        for window in hex_all.as_bytes().chunks(16).take(64) {
            let needle = std::str::from_utf8(window).unwrap();
            assert!(
                !rendered.contains(needle),
                "Debug output leaked hex key material: {needle}"
            );
        }

        // 2. No `Vec<u8>` decimal rendering — the shape `[13, 245, 7, ...]` a derived
        //    Debug would produce. The first few bytes are enough to catch it.
        let decimal_prefix = format!("{}, {}, {}", secret[0], secret[1], secret[2]);
        assert!(
            !rendered.contains(&decimal_prefix),
            "Debug output leaked decimal key material: {decimal_prefix}"
        );

        // 3. The length is public and useful; the bytes are not.
        assert!(
            rendered.contains("2560"),
            "Debug output should still report the key length"
        );
    }
}

#[test]
fn test_private_key_equality_is_value_based_and_scheme_aware() {
    let a = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let a_again = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let b = Keypair::generate(SignatureSchemeId::Dilithium2, [2u8; 32]).unwrap();

    assert_eq!(
        a.private_key(),
        a_again.private_key(),
        "Same seed must derive an equal private key"
    );
    assert_ne!(
        a.private_key(),
        b.private_key(),
        "Different seeds must derive different private keys"
    );
}

#[test]
fn test_private_key_constant_time_equality_holds_for_near_misses() {
    // The constant-time path must still be *correct*: keys differing in exactly one bit,
    // at the front and at the back, must compare unequal.
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [9u8; 32]).unwrap();
    let original = kp.private_key().clone();

    for idx in [0usize, 1, 1279, 2559] {
        let mut bytes = original.expose_secret().to_vec();
        bytes[idx] ^= 0x01;
        let mutated = PrivateKey::new(SignatureSchemeId::Dilithium2, bytes);
        assert_ne!(
            original, mutated,
            "A single flipped bit at index {idx} must make keys unequal"
        );
    }
}

#[test]
fn test_private_key_zeroize_now_wipes_material() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [3u8; 32]).unwrap();
    let mut sk = kp.private_key().clone();
    assert_ne!(sk.expose_secret(), vec![0u8; 2560].as_slice());

    sk.zeroize_now();
    assert!(
        sk.expose_secret().iter().all(|&b| b == 0),
        "zeroize_now must wipe every byte of key material"
    );
}

#[test]
fn test_signature_bytes_are_non_trivial() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let sig = kp.sign(b"test payload", None).unwrap();
    assert_ne!(sig.bytes, vec![0u8; 2420], "Signature must not be all-zero");
    assert_ne!(
        sig.bytes,
        vec![0xFFu8; 2420],
        "Signature must not be all-0xFF"
    );
}

#[test]
fn test_signature_size_is_constant_regardless_of_message_size() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();

    let sig_empty = kp.sign(b"", None).unwrap();
    let sig_small = kp.sign(b"x", None).unwrap();
    let sig_medium = kp.sign(&vec![0xABu8; 1024], None).unwrap();
    let sig_large = kp.sign(&vec![0xCDu8; 1024 * 1024], None).unwrap();

    assert_eq!(
        sig_empty.bytes.len(),
        2420,
        "Empty message: signature must be 2420 bytes"
    );
    assert_eq!(
        sig_small.bytes.len(),
        2420,
        "Small message: signature must be 2420 bytes"
    );
    assert_eq!(
        sig_medium.bytes.len(),
        2420,
        "1KB message: signature must be 2420 bytes"
    );
    assert_eq!(
        sig_large.bytes.len(),
        2420,
        "1MB message: signature must be 2420 bytes"
    );

    println!("✓ ML-DSA-44 signature size is constant (2420 B) regardless of message size");
}

// ══════════════════════════════════════════════════════════════════════════
// GROUP 5: Scheme field correctness
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_scheme_field_on_generated_keypair_is_dilithium2() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    assert_eq!(
        kp.public_key().scheme,
        SignatureSchemeId::Dilithium2,
        "Public key scheme field must be Dilithium2"
    );
    assert_eq!(
        *kp.private_key().scheme(),
        SignatureSchemeId::Dilithium2,
        "Private key scheme field must be Dilithium2"
    );
}

#[test]
fn test_scheme_field_on_produced_signature_is_dilithium2() {
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let sig = kp.sign(b"test", None).unwrap();
    assert_eq!(
        sig.scheme,
        SignatureSchemeId::Dilithium2,
        "Signature scheme field must be Dilithium2"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// GROUP 6: Multi-validator signing
// Simulates Q-BFT validator set: each signs same block hash; cross-key
// verification must fail (no key confusion across validator identities).
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_validator_each_signs_block_hash_all_self_verify() {
    let block_hash = b"block-hash:0xdeadbeef";
    let ctx = b"huxplex-mainnet:block:preprepare:v1";

    let validators: Vec<Keypair> = (1u8..=5)
        .map(|i| Keypair::generate(SignatureSchemeId::Dilithium2, [i; 32]).unwrap())
        .collect();

    let sigs: Vec<_> = validators
        .iter()
        .map(|kp| kp.sign(block_hash, Some(ctx)).unwrap())
        .collect();

    for (i, (kp, sig)) in validators.iter().zip(sigs.iter()).enumerate() {
        assert!(
            kp.public_key().verify(block_hash, sig, Some(ctx)).unwrap(),
            "Validator {i} must verify its own signature"
        );
    }

    println!("✓ 5-of-5 validator self-verification roundtrip (Q-BFT PrePrepare context)");
}

#[test]
fn test_multi_validator_cross_key_verification_fails() {
    let block_hash = b"block-hash:0xdeadbeef";
    let ctx = b"huxplex-mainnet:block:preprepare:v1";

    let v1 = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let v2 = Keypair::generate(SignatureSchemeId::Dilithium2, [2u8; 32]).unwrap();
    let v3 = Keypair::generate(SignatureSchemeId::Dilithium2, [3u8; 32]).unwrap();

    let sig_v1 = v1.sign(block_hash, Some(ctx)).unwrap();
    let sig_v2 = v2.sign(block_hash, Some(ctx)).unwrap();

    // Correct keys verify
    assert!(
        v1.public_key()
            .verify(block_hash, &sig_v1, Some(ctx))
            .unwrap()
    );
    assert!(
        v2.public_key()
            .verify(block_hash, &sig_v2, Some(ctx))
            .unwrap()
    );

    // Cross-key verification must fail
    assert!(
        !v2.public_key()
            .verify(block_hash, &sig_v1, Some(ctx))
            .unwrap(),
        "v2 must not verify v1's signature"
    );
    assert!(
        !v1.public_key()
            .verify(block_hash, &sig_v2, Some(ctx))
            .unwrap(),
        "v1 must not verify v2's signature"
    );
    assert!(
        !v3.public_key()
            .verify(block_hash, &sig_v1, Some(ctx))
            .unwrap(),
        "v3 must not verify v1's signature"
    );

    println!("✓ Cross-validator signature confusion correctly rejected");
}

#[test]
fn test_prepare_and_commit_phase_contexts_are_domain_separated() {
    // A PREPARE phase signature must not verify under COMMIT context and vice versa.
    // Prevents a Byzantine validator from replaying a prepare vote as a commit.
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [42u8; 32]).unwrap();
    let block_hash = b"block-hash:0xdeadbeef";

    let prepare_ctx = b"huxplex-mainnet:block:prepare:v1";
    let commit_ctx = b"huxplex-mainnet:block:commit:v1";

    let sig_prepare = kp.sign(block_hash, Some(prepare_ctx)).unwrap();

    assert!(
        kp.public_key()
            .verify(block_hash, &sig_prepare, Some(prepare_ctx))
            .unwrap(),
        "Prepare sig must verify under prepare context"
    );
    assert!(
        !kp.public_key()
            .verify(block_hash, &sig_prepare, Some(commit_ctx))
            .unwrap(),
        "Prepare sig must NOT verify under commit context — prevents phase replay"
    );

    println!("✓ Q-BFT phase contexts (prepare/commit) are domain-separated");
}
