pub mod bip32;
pub mod error;
pub mod kem;
pub mod privatekey;
pub mod publickey;
pub mod signature;
pub mod signaturescheme;

#[cfg(test)]

mod ml_dsa_44_tests {
    use crate::crypto::{
        bip32::derive_mldsa_seed, signature::Keypair, signaturescheme::SignatureSchemeId,
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
        assert_eq!(keypair.private_key().bytes.len(), 2560); // SECRET_KEY_BYTES - updated
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

        let keypair1 = Keypair::generate(SignatureSchemeId::Dilithium2, seed)
            .expect("Generation should succeed");
        let keypair2 = Keypair::generate(SignatureSchemeId::Dilithium2, seed)
            .expect("Generation should succeed");

        assert_eq!(
            keypair1.public_key().bytes,
            keypair2.public_key().bytes,
            "Same seed must produce identical public keys"
        );
        assert_eq!(
            keypair1.private_key().bytes,
            keypair2.private_key().bytes,
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
    fn test_hd_wallet_derivation() {
        let bytes = hex::decode(HEXSEED).expect("Must be valid hex");
        let master_seed: [u8; 64] = bytes.as_slice().try_into().expect("Seed must be 64 bytes");

        // Derive 5 validators from master seed
        let validators: Vec<_> = (0..5)
            .map(|index| {
                let seed = derive_mldsa_seed(master_seed, index);
                Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap()
            })
            .collect();

        // All validators have different keys
        for i in 0..validators.len() {
            for j in i + 1..validators.len() {
                assert_ne!(
                    validators[i].public_key().bytes,
                    validators[j].public_key().bytes,
                    "Validators {} and {} should have different keys",
                    i,
                    j
                );
            }
        }

        // But derivation is reproducible
        let validator_0_again = {
            let seed = derive_mldsa_seed(master_seed, 0);
            Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap()
        };
        assert_eq!(
            validators[0].public_key().bytes,
            validator_0_again.public_key().bytes,
            "Derivation must be deterministic"
        );

        println!("✓ HD wallet derivation working (5 validators from master seed)");
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let kp1 = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
        let kp2 = Keypair::generate(SignatureSchemeId::Dilithium2, [2u8; 32]).unwrap();

        assert_ne!(kp1.public_key().bytes, kp2.public_key().bytes);
        assert_ne!(kp1.private_key().bytes, kp2.private_key().bytes);

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
            kp.private_key().bytes,
            vec![0u8; 2560],
            "ML-DSA-44 secret key must not be all-zero"
        );
        assert_ne!(
            kp.private_key().bytes,
            vec![0xFFu8; 2560],
            "ML-DSA-44 secret key must not be all-0xFF"
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
            kp.private_key().scheme,
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

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 7: Canonical context string inventory
    // Every context string defined in the Huxplex spec must:
    //   (a) self-verify correctly
    //   (b) not cross-verify with any other spec context
    // ══════════════════════════════════════════════════════════════════════════

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

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 9: BIP32-ML specifics
    // Path: m/44'/931931'/0'/0'/{index}'
    // All indexes hardened. Coin type 931931' is Huxplex-reserved.
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_bip32_derived_seed_is_32_bytes_and_non_trivial() {
        let master: [u8; 64] = [0x11u8; 64];
        let seed = derive_mldsa_seed(master, 0);

        assert_eq!(
            seed.len(),
            32,
            "Derived ML-DSA seed must be exactly 32 bytes"
        );
        assert_ne!(seed, [0u8; 32], "Derived seed must be non-zero");
        assert_ne!(seed, [0xFFu8; 32], "Derived seed must not be all-0xFF");
    }

    #[test]
    fn test_bip32_high_index_derivation_produces_valid_keypairs() {
        let master: [u8; 64] = [0x11u8; 64];

        let boundary_indexes: [u32; 5] = [0, 100, 1_000, 10_000, 65_535];
        let seeds: Vec<[u8; 32]> = boundary_indexes
            .iter()
            .map(|&i| derive_mldsa_seed(master, i))
            .collect();

        // All seeds are distinct
        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert_ne!(
                    seeds[i], seeds[j],
                    "Seeds at indexes {} and {} must differ",
                    boundary_indexes[i], boundary_indexes[j]
                );
            }
        }

        // All seeds produce valid keypairs with correct sizes
        for (idx, seed) in boundary_indexes.iter().zip(seeds.iter()) {
            let kp = Keypair::generate(SignatureSchemeId::Dilithium2, *seed).unwrap();
            assert_eq!(
                kp.public_key().bytes.len(),
                1312,
                "PK at index {idx} must be 1312 B"
            );
            assert_eq!(
                kp.private_key().bytes.len(),
                2560,
                "SK at index {idx} must be 2560 B"
            );
        }

        println!(
            "✓ BIP32-ML high-index derivation: indexes {:?} all produce valid keypairs",
            boundary_indexes
        );
    }

    #[test]
    fn test_bip32_different_master_seeds_produce_distinct_hd_trees() {
        let master_a: [u8; 64] = [0x11u8; 64];
        let master_b: [u8; 64] = [0x22u8; 64];

        // Same child index, different master → different child seeds
        for index in 0u32..5 {
            let seed_a = derive_mldsa_seed(master_a, index);
            let seed_b = derive_mldsa_seed(master_b, index);
            assert_ne!(
                seed_a, seed_b,
                "Index {index}: different master seeds must produce different child seeds"
            );
        }

        println!("✓ Master seed isolation: two HD trees share no child key material");
    }

    #[test]
    fn test_bip32_twenty_validators_from_same_master_all_unique_and_reproducible() {
        let bytes = hex::decode(HEXSEED).expect("Must be valid hex");
        let master: [u8; 64] = bytes.as_slice().try_into().expect("Seed must be 64 bytes");

        let validators: Vec<Keypair> = (0u32..20)
            .map(|i| {
                let seed = derive_mldsa_seed(master, i);
                Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap()
            })
            .collect();

        // All 20 public keys are unique
        for i in 0..validators.len() {
            for j in (i + 1)..validators.len() {
                assert_ne!(
                    validators[i].public_key().bytes,
                    validators[j].public_key().bytes,
                    "Validators {i} and {j} must have distinct public keys"
                );
            }
        }

        // Reproducible: re-derive validator 10 and confirm it matches
        let seed_10 = derive_mldsa_seed(master, 10);
        let v10_again = Keypair::generate(SignatureSchemeId::Dilithium2, seed_10).unwrap();
        assert_eq!(
            validators[10].public_key().bytes,
            v10_again.public_key().bytes,
            "Validator 10 derivation must be reproducible"
        );

        println!("✓ 20-validator HD set: all unique, re-derivation deterministic");
    }

    #[test]
    fn test_bip32_derived_validator_can_sign_and_verify_all_spec_contexts() {
        let bytes = hex::decode(HEXSEED).expect("Must be valid hex");
        let master: [u8; 64] = bytes.as_slice().try_into().expect("Seed must be 64 bytes");
        let seed = derive_mldsa_seed(master, 0);
        let kp = Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap();

        let contexts_and_messages: &[(&[u8], &[u8])] = &[
            (b"huxplex-mainnet:tx:v1", b"Transfer 100 HUX"),
            (
                b"huxplex-mainnet:block:preprepare:v1",
                b"block-hash:0xdeadbeef",
            ),
            (b"huxplex-mainnet:vc:v1", b"vc-hash:0xcafebabe"),
            (b"huxplex-mainnet:intent:v1", b"intent-hash:0xabcdef"),
        ];

        for (ctx, msg) in contexts_and_messages {
            let sig = kp.sign(msg, Some(ctx)).unwrap();
            assert!(
                kp.public_key().verify(msg, &sig, Some(ctx)).unwrap(),
                "HD-derived validator must sign/verify under context '{}'",
                std::str::from_utf8(ctx).unwrap()
            );
        }

        println!("✓ HD-derived validator (index 0) signs correctly under all spec contexts");
    }
}

#[cfg(test)]
mod ml_kem_768_tests {
    use crate::crypto::kem::*;

    // ── Fixed randomness for reproducible tests ──────────────────────────────
    const KEYGEN_RAND_A: [u8; 64] = [0x11u8; 64];
    const KEYGEN_RAND_B: [u8; 64] = [0x22u8; 64];
    const ENCAP_RAND_1: [u8; 32] = [0xAAu8; 32];
    const ENCAP_RAND_2: [u8; 32] = [0xBBu8; 32];

    #[test]
    fn test_keygen_output_sizes_match_fips203_spec() {
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);

        // These constants are non-negotiable per FIPS 203 ML-KEM-768
        assert_eq!(
            EK_SIZE, 1184,
            "EK_SIZE constant must be 1184 (FIPS 203 ML-KEM-768)"
        );
        assert_eq!(
            DK_SIZE, 2400,
            "DK_SIZE constant must be 2400 (FIPS 203 ML-KEM-768)"
        );

        assert_eq!(
            ek.len(),
            EK_SIZE,
            "Encapsulation key must be {} bytes",
            EK_SIZE
        );
        assert_eq!(
            dk.len(),
            DK_SIZE,
            "Decapsulation key must be {} bytes",
            DK_SIZE
        );
    }
    #[test]
    fn test_ciphertext_size_constant_matches_fips203_spec() {
        assert_eq!(CT_SIZE, 1088, "CT_SIZE must be 1088 (FIPS 203 ML-KEM-768)");

        let (ek, _dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _ss) = kem768_encapsulate(ek, ENCAP_RAND_1);
        assert_eq!(
            ct.len(),
            CT_SIZE,
            "Returned ciphertext must match CT_SIZE constant"
        );
    }
    // ── 2. CORRECTNESS: shared secret agreement ───────────────────────────────

    #[test]
    fn test_encap_decap_roundtrip_both_sides_agree() {
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);

        let (ct, ss_encap) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss_decap = kem768_decapsulate(dk, ct);

        assert_eq!(
            ss_encap, ss_decap,
            "Encapsulator and decapsulator must derive an identical 32-byte shared secret"
        );
    }

    #[test]
    fn test_shared_secret_is_non_trivial() {
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, ss_enc) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss_dec = kem768_decapsulate(dk, ct);

        assert_ne!(
            ss_enc, [0u8; 32],
            "Encapsulated shared secret must never be all-zero"
        );
        assert_ne!(
            ss_dec, [0u8; 32],
            "Decapsulated shared secret must never be all-zero"
        );
        assert_ne!(
            ss_enc, [0xFFu8; 32],
            "Shared secret must not be trivially all-0xFF"
        );
    }

    // ── 3. DETERMINISM ────────────────────────────────────────────────────────

    #[test]
    fn test_keygen_is_deterministic_same_randomness_same_keys() {
        let (ek1, dk1) = kem768_keygen(KEYGEN_RAND_A);
        let (ek2, dk2) = kem768_keygen(KEYGEN_RAND_A);

        assert_eq!(
            ek1, ek2,
            "Same keygen randomness must produce an identical EK"
        );
        assert_eq!(
            dk1, dk2,
            "Same keygen randomness must produce an identical DK"
        );
    }

    #[test]
    fn test_encapsulation_is_deterministic_same_inputs_same_outputs() {
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);

        let (ct1, ss1) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let (ct2, ss2) = kem768_encapsulate(ek, ENCAP_RAND_1);

        assert_eq!(
            ct1, ct2,
            "Same (EK, rand) must produce an identical ciphertext"
        );
        assert_eq!(
            ss1, ss2,
            "Same (EK, rand) must produce an identical shared secret"
        );

        // Cross-check: both ciphertexts decapsulate to the same secret
        let ss_dec1 = kem768_decapsulate(dk, ct1);
        let ss_dec2 = kem768_decapsulate(dk, ct2);
        assert_eq!(ss_dec1, ss_dec2);
    }

    // ── 4. KEY SEPARATION ─────────────────────────────────────────────────────

    #[test]
    fn test_different_keygen_randomness_produces_different_keys() {
        let (ek1, dk1) = kem768_keygen(KEYGEN_RAND_A);
        let (ek2, dk2) = kem768_keygen(KEYGEN_RAND_B);

        assert_ne!(ek1, ek2, "Different randomness must produce different EKs");
        assert_ne!(dk1, dk2, "Different randomness must produce different DKs");
    }

    #[test]
    fn test_different_encap_randomness_produces_different_ct_and_ss() {
        let (ek, _dk) = kem768_keygen(KEYGEN_RAND_A);

        let (ct1, ss1) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let (ct2, ss2) = kem768_encapsulate(ek, ENCAP_RAND_2);

        assert_ne!(
            ct1, ct2,
            "Different encap randomness must produce different ciphertexts"
        );
        assert_ne!(
            ss1, ss2,
            "Different encap randomness must produce different shared secrets"
        );
    }

    // ── 5. IND-CCA2 / IMPLICIT REJECTION ─────────────────────────────────────
    //
    // ML-KEM (FIPS 203) provides implicit rejection: a tampered ciphertext or
    // wrong key does NOT return an error — it returns a pseudorandom value
    // derived from H(dk, ct). This is the IND-CCA2 security guarantee.
    // The correct behaviour is: shared secrets DIFFER, not that decap errors.

    #[test]
    fn test_wrong_decap_key_yields_different_shared_secret_implicit_rejection() {
        let (ek_a, _dk_a) = kem768_keygen(KEYGEN_RAND_A);
        let (_ek_b, dk_b) = kem768_keygen(KEYGEN_RAND_B);

        let (ct, ss_correct) = kem768_encapsulate(ek_a, ENCAP_RAND_1);

        // Wrong key: decapsulation succeeds but yields a DIFFERENT pseudorandom secret
        let ss_wrong = kem768_decapsulate(dk_b, ct);

        assert_ne!(
            ss_correct, ss_wrong,
            "Wrong decap key must yield a different shared secret (IND-CCA2 implicit rejection)"
        );
    }

    #[test]
    fn test_single_bit_flip_in_ciphertext_yields_different_shared_secret() {
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, ss_correct) = kem768_encapsulate(ek, ENCAP_RAND_1);

        // Flip one bit in the ciphertext (first byte)
        let mut tampered = ct;
        tampered[0] ^= 0x01;
        let ss_tampered = kem768_decapsulate(dk, tampered);

        assert_ne!(
            ss_correct, ss_tampered,
            "Single-bit flip must produce a different shared secret (IND-CCA2)"
        );
    }

    #[test]
    fn test_last_byte_flip_in_ciphertext_yields_different_shared_secret() {
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, ss_correct) = kem768_encapsulate(ek, ENCAP_RAND_1);

        let mut tampered = ct;
        tampered[CT_SIZE - 1] ^= 0xFF;
        let ss_tampered = kem768_decapsulate(dk, tampered);

        assert_ne!(
            ss_correct, ss_tampered,
            "Last-byte flip must produce a different shared secret"
        );
    }

    #[test]
    fn test_all_zeros_ciphertext_yields_different_shared_secret() {
        let (_ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ek2, dk2) = kem768_keygen(KEYGEN_RAND_B);

        let (ct_valid, ss_valid) = kem768_encapsulate(ek2, ENCAP_RAND_1);
        let ss_valid_dec = kem768_decapsulate(dk2, ct_valid);

        // All-zero ciphertext against a real key
        let ss_zero_ct = kem768_decapsulate(dk, [0u8; CT_SIZE]);

        // Must be different from any legitimately encapsulated secret
        assert_ne!(
            ss_valid_dec, ss_zero_ct,
            "All-zero ciphertext must not accidentally match a valid shared secret"
        );
    }

    // ── 7. SESSION KEY DERIVATION ─────────────────────────────────────────────

    #[test]
    fn test_derive_session_key_is_deterministic() {
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];

        let key1 = kem768_derive_session_key(ss, peer_a, peer_b, None, None);
        let key2 = kem768_derive_session_key(ss, peer_a, peer_b, None, None);

        assert_eq!(key1, key2, "Session key derivation must be deterministic");
        assert_ne!(key1, [0u8; 32], "Derived session key must be non-trivial");
    }

    #[test]
    fn test_derive_session_key_is_direction_asymmetric() {
        // Handshake direction (initiator, responder) is baked into the key.
        // key(A→B) must differ from key(B→A) to prevent reflection attacks.
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];

        let key_ab = kem768_derive_session_key(ss, peer_a, peer_b, None, None);
        let key_ba = kem768_derive_session_key(ss, peer_b, peer_a, None, None);

        assert_ne!(
            key_ab, key_ba,
            "Session key must differ based on initiator/responder direction"
        );
    }

    #[test]
    fn test_different_shared_secrets_produce_different_session_keys() {
        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];

        let (ek1, dk1) = kem768_keygen(KEYGEN_RAND_A);
        let (ct1, _) = kem768_encapsulate(ek1, ENCAP_RAND_1);
        let ss1 = kem768_decapsulate(dk1, ct1);

        let (ek2, dk2) = kem768_keygen(KEYGEN_RAND_B);
        let (ct2, _) = kem768_encapsulate(ek2, ENCAP_RAND_2);
        let ss2 = kem768_decapsulate(dk2, ct2);

        let sk1 = kem768_derive_session_key(ss1, peer_a, peer_b, None, None);
        let sk2 = kem768_derive_session_key(ss2, peer_a, peer_b, None, None);

        assert_ne!(
            sk1, sk2,
            "Different shared secrets must yield different session keys"
        );
    }
    #[test]
    fn test_same_shared_secret_different_peer_ids_different_session_keys() {
        // A session key must be bound to the specific peer pair.
        // A third party with the same SS must not derive the same key.
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];
        let peer_c = [0x03u8; 32];

        let key_ab = kem768_derive_session_key(ss, peer_a, peer_b, None, None);
        let key_ac = kem768_derive_session_key(ss, peer_a, peer_c, None, None);

        assert_ne!(
            key_ab, key_ac,
            "Different peer IDs must produce different session keys even with the same shared secret"
        );
    }
    #[test]
    fn test_session_key_with_salt_differs_from_without_salt() {
        // salt is intended for QRNG-sourced per-epoch nonces;
        // two epochs must produce different session keys from the same SS.
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];

        let key_no_salt = kem768_derive_session_key(ss, peer_a, peer_b, None, None);
        let key_epoch_0 =
            kem768_derive_session_key(ss, peer_a, peer_b, Some(b"epoch-qrng-0"), None);
        let key_epoch_1 =
            kem768_derive_session_key(ss, peer_a, peer_b, Some(b"epoch-qrng-1"), None);

        assert_ne!(
            key_no_salt, key_epoch_0,
            "Salt must change the derived session key"
        );
        assert_ne!(
            key_epoch_0, key_epoch_1,
            "Different epoch salts must produce different session keys"
        );
        assert_ne!(key_no_salt, key_epoch_1);
    }

    #[test]
    fn test_session_key_same_salt_is_deterministic() {
        // A validator re-deriving from the same epoch seed must get the same key.
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];
        let salt = b"epoch-qrng-42";

        let key1 = kem768_derive_session_key(ss, peer_a, peer_b, Some(salt), None);
        let key2 = kem768_derive_session_key(ss, peer_a, peer_b, Some(salt), None);

        assert_eq!(
            key1, key2,
            "Same salt must deterministically reproduce the same session key"
        );
    }

    #[test]
    fn test_session_key_with_protocol_label_differs_from_without() {
        // protocol_label provides domain separation across different uses of the same SS.
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];

        let key_no_label = kem768_derive_session_key(ss, peer_a, peer_b, None, None);
        let key_with_label = kem768_derive_session_key(
            ss,
            peer_a,
            peer_b,
            None,
            Some(b"huxplex-mainnet:tls:handshake:v1"),
        );

        assert_ne!(
            key_no_label, key_with_label,
            "Protocol label must alter the derived session key"
        );
    }

    #[test]
    fn test_session_key_mainnet_and_testnet_labels_are_domain_separated() {
        // A session key derived on mainnet must be cryptographically distinct
        // from one derived on testnet — even with the same KEM shared secret and peer IDs.
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];

        let key_mainnet = kem768_derive_session_key(
            ss,
            peer_a,
            peer_b,
            None,
            Some(b"huxplex-mainnet:tls:handshake:v1"),
        );
        let key_testnet = kem768_derive_session_key(
            ss,
            peer_a,
            peer_b,
            None,
            Some(b"huxplex-testnet:tls:handshake:v1"),
        );

        assert_ne!(
            key_mainnet, key_testnet,
            "Mainnet and testnet session keys must be distinct — prevents cross-network connection reuse"
        );

        println!("✓ Mainnet/testnet session key domain separation enforced");
    }

    #[test]
    fn test_session_key_gossip_and_tls_labels_are_domain_separated() {
        // The same SS and peers must yield different keys for different protocol roles.
        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, _) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let ss = kem768_decapsulate(dk, ct);

        let peer_a = [0x01u8; 32];
        let peer_b = [0x02u8; 32];

        let key_tls = kem768_derive_session_key(
            ss,
            peer_a,
            peer_b,
            None,
            Some(b"huxplex-mainnet:tls:handshake:v1"),
        );
        let key_gossip = kem768_derive_session_key(
            ss,
            peer_a,
            peer_b,
            None,
            Some(b"huxplex-mainnet:gossip:block:v1"),
        );

        assert_ne!(
            key_tls, key_gossip,
            "TLS and gossip protocol labels must produce distinct session keys"
        );
    }

    // ── Group 8: Full PQTLS handshake simulation (spec Phases 1–4) ───────────

    #[test]
    fn test_pqtls_handshake_simulation_both_sides_derive_same_session_key() {
        use crate::crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};

        // Phase 1 — Initiator → Responder: ClientHello + ML-KEM-768 EK
        // Phase 2 — Responder → Initiator: ML-KEM-768 ciphertext
        //                                 + ML-DSA-44 signature over transcript
        // Phase 3 — Initiator verifies sig; both decapsulate to same SS
        // Phase 4 — Both derive identical ChaCha20-Poly1305 session key

        let responder_dsa_kp =
            Keypair::generate(SignatureSchemeId::Dilithium2, [0xBBu8; 32]).unwrap();
        let (responder_ek, responder_dk) = kem768_keygen(KEYGEN_RAND_B);

        // ── Phase 1: Initiator transmits responder's EK in ClientHello ──
        let client_hello_ek = responder_ek;

        // ── Phase 2: Responder encapsulates; signs transcript ──
        let (ct, ss_responder) = kem768_encapsulate(client_hello_ek, ENCAP_RAND_1);

        let mut transcript = Vec::with_capacity(EK_SIZE + CT_SIZE);
        transcript.extend_from_slice(&client_hello_ek);
        transcript.extend_from_slice(&ct);

        let handshake_ctx = b"huxplex-mainnet:tls:handshake:v1";
        let transcript_sig = responder_dsa_kp
            .sign(&transcript, Some(handshake_ctx))
            .expect("Responder ML-DSA-44 signing must succeed");

        // ── Phase 3: Initiator verifies transcript signature ──
        let sig_valid = responder_dsa_kp
            .public_key()
            .verify(&transcript, &transcript_sig, Some(handshake_ctx))
            .expect("Transcript signature verification must not error");
        assert!(sig_valid, "Transcript ML-DSA-44 signature must verify");

        let ss_initiator = kem768_decapsulate(responder_dk, ct);
        assert_eq!(
            ss_initiator, ss_responder,
            "PQTLS Phase 3: both sides must hold identical shared secrets"
        );

        // ── Phase 4: Both derive identical 32-byte ChaCha20-Poly1305 session key ──
        let initiator_pid = [0x01u8; 32];
        let responder_pid = [0x02u8; 32];
        let label = b"huxplex-mainnet:tls:handshake:v1";

        let key_initiator = kem768_derive_session_key(
            ss_initiator,
            initiator_pid,
            responder_pid,
            None,
            Some(label),
        );
        let key_responder = kem768_derive_session_key(
            ss_responder,
            initiator_pid,
            responder_pid,
            None,
            Some(label),
        );

        assert_eq!(
            key_initiator, key_responder,
            "PQTLS Phase 4: both sides must derive identical ChaCha20-Poly1305 session keys"
        );
        assert_ne!(key_initiator, [0u8; 32], "Session key must be non-trivial");

        println!("✓ PQTLS handshake complete");
        println!(
            "  EK: {} B | CT: {} B | SS: 32 B | Session key: 32 B",
            EK_SIZE, CT_SIZE
        );
    }

    // ── Group 9: Context binding and replay prevention ────────────────────────

    #[test]
    fn test_pqtls_wrong_network_context_fails_transcript_verification() {
        use crate::crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};

        let responder_kp = Keypair::generate(SignatureSchemeId::Dilithium2, [0xBBu8; 32]).unwrap();
        let (responder_ek, _dk) = kem768_keygen(KEYGEN_RAND_B);
        let (ct, _ss) = kem768_encapsulate(responder_ek, ENCAP_RAND_1);

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&responder_ek);
        transcript.extend_from_slice(&ct);

        let mainnet_ctx = b"huxplex-mainnet:tls:handshake:v1";
        let testnet_ctx = b"huxplex-testnet:tls:handshake:v1";

        let sig = responder_kp.sign(&transcript, Some(mainnet_ctx)).unwrap();

        let valid_testnet = responder_kp
            .public_key()
            .verify(&transcript, &sig, Some(testnet_ctx))
            .unwrap();
        assert!(
            !valid_testnet,
            "Mainnet handshake transcript sig must not verify on testnet"
        );

        let valid_none = responder_kp
            .public_key()
            .verify(&transcript, &sig, None)
            .unwrap();
        assert!(
            !valid_none,
            "Context-bound transcript sig must fail with no context"
        );

        println!("✓ PQTLS handshake context binding prevents cross-network replay");
    }

    #[test]
    fn test_tampered_transcript_fails_mldsa_verification() {
        use crate::crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};

        let responder_kp = Keypair::generate(SignatureSchemeId::Dilithium2, [0xBBu8; 32]).unwrap();
        let (responder_ek, _dk) = kem768_keygen(KEYGEN_RAND_B);
        let (ct, _ss) = kem768_encapsulate(responder_ek, ENCAP_RAND_1);

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&responder_ek);
        transcript.extend_from_slice(&ct);

        let ctx = b"huxplex-mainnet:tls:handshake:v1";
        let sig = responder_kp.sign(&transcript, Some(ctx)).unwrap();

        // Flip one byte in the EK portion of the transcript
        transcript[0] ^= 0xFF;
        let valid = responder_kp
            .public_key()
            .verify(&transcript, &sig, Some(ctx))
            .unwrap();

        assert!(
            !valid,
            "Tampered transcript must fail ML-DSA-44 verification"
        );
        println!("✓ Transcript integrity enforced by ML-DSA-44");
    }

    #[test]
    fn test_ek_substitution_mitm_fails_transcript_verification() {
        // An active attacker intercepts ClientHello and replaces the responder's EK
        // with their own. The ML-DSA-44 transcript signature binds the original EK,
        // so the victim initiator detects the substitution.
        use crate::crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};

        let responder_kp = Keypair::generate(SignatureSchemeId::Dilithium2, [0xBBu8; 32]).unwrap();
        let (responder_ek, _dk) = kem768_keygen(KEYGEN_RAND_B);
        let (ct, _ss) = kem768_encapsulate(responder_ek, ENCAP_RAND_1);

        let mut original_transcript = Vec::new();
        original_transcript.extend_from_slice(&responder_ek);
        original_transcript.extend_from_slice(&ct);

        let ctx = b"huxplex-mainnet:tls:handshake:v1";
        let sig = responder_kp.sign(&original_transcript, Some(ctx)).unwrap();

        // Attacker swaps in their own EK
        let (attacker_ek, _) = kem768_keygen([0xDDu8; 64]);
        let mut mitm_transcript = Vec::new();
        mitm_transcript.extend_from_slice(&attacker_ek);
        mitm_transcript.extend_from_slice(&ct);

        let valid = responder_kp
            .public_key()
            .verify(&mitm_transcript, &sig, Some(ctx))
            .unwrap();

        assert!(
            !valid,
            "EK substitution (MITM) must be detected by ML-DSA-44 transcript verification"
        );
        println!("✓ MITM EK substitution prevented by transcript signature");
    }

    #[test]
    fn test_ct_substitution_yields_different_shared_secret_and_breaks_handshake() {
        // An attacker replaces the responder's ciphertext with their own.
        // IND-CCA2 implicit rejection: initiator decapsulates to a DIFFERENT pseudorandom secret
        // → both sides end up with different session keys → connection silently fails to establish.
        let (responder_ek, responder_dk) = kem768_keygen(KEYGEN_RAND_B);
        let (_attacker_ek, attacker_dk) = kem768_keygen([0xDDu8; 64]);

        // Responder's legitimate encapsulation
        let (ct_legit, ss_responder) = kem768_encapsulate(responder_ek, ENCAP_RAND_1);

        // Attacker re-encapsulates into responder's EK with different randomness
        let (ct_attacker, _ss_attacker) = kem768_encapsulate(responder_ek, ENCAP_RAND_2);

        // Initiator receives attacker's CT — decapsulates to a DIFFERENT secret
        let ss_from_attacker_ct = kem768_decapsulate(responder_dk, ct_attacker);
        let ss_from_legit_ct = kem768_decapsulate(responder_dk, ct_legit);

        assert_eq!(
            ss_from_legit_ct, ss_responder,
            "Legitimate CT must decapsulate to responder's shared secret"
        );
        assert_ne!(
            ss_from_attacker_ct, ss_responder,
            "Attacker-substituted CT must yield a DIFFERENT shared secret (IND-CCA2)"
        );

        // Consequence: initiator and responder derive different session keys → handshake fails
        let _ = attacker_dk; // attacker cannot recover the session key either
        println!("✓ CT substitution detected via session key mismatch (IND-CCA2 property)");
    }

    // ── Group 10: Type separation ─────────────────────────────────────────────

    #[test]
    fn test_kem_and_mldsa_key_sizes_are_distinct_no_type_confusion() {
        // A node must never accept an ML-KEM EK (1184 B) in place of
        // an ML-DSA-44 PK (1312 B) or vice versa.
        use crate::crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};

        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let dsa_kp = Keypair::generate(SignatureSchemeId::Dilithium2, [0x11u8; 32]).unwrap();

        assert_ne!(
            ek.len(),
            dsa_kp.public_key().bytes.len(),
            "ML-KEM EK ({} B) must not share size with ML-DSA-44 PK ({} B)",
            EK_SIZE,
            dsa_kp.public_key().bytes.len()
        );
        assert_ne!(
            dk.len(),
            dsa_kp.private_key().bytes.len(),
            "ML-KEM DK ({} B) must not share size with ML-DSA-44 SK ({} B)",
            DK_SIZE,
            dsa_kp.private_key().bytes.len()
        );
        assert_ne!(
            CT_SIZE,
            dsa_kp.public_key().bytes.len(),
            "ML-KEM CT must not share size with ML-DSA-44 PK"
        );

        println!(
            "✓ No key size collisions — ML-KEM-768: EK={} B DK={} B CT={} B | ML-DSA-44: PK=1312 B SK=2560 B",
            EK_SIZE, DK_SIZE, CT_SIZE
        );
    }

    // ── Group 11: Edge cases (panic freedom) ─────────────────────────────────

    #[test]
    fn test_zero_randomness_keygen_correctness_and_no_panic() {
        // Must never panic. Correctness must hold even on degenerate entropy.
        // In production, kem768_keygen is always called with QRNG-sourced randomness.
        let (ek, dk) = kem768_keygen([0u8; 64]);

        assert_eq!(ek.len(), EK_SIZE);
        assert_eq!(dk.len(), DK_SIZE);

        let (ct, ss_enc) = kem768_encapsulate(ek, [0u8; 32]);
        let ss_dec = kem768_decapsulate(dk, ct);
        assert_eq!(
            ss_enc, ss_dec,
            "Zero-randomness keys must still satisfy ML-KEM correctness"
        );
    }

    #[test]
    fn test_max_randomness_keygen_correctness_and_no_panic() {
        let (ek, dk) = kem768_keygen([0xFFu8; 64]);

        assert_eq!(ek.len(), EK_SIZE);
        assert_eq!(dk.len(), DK_SIZE);

        let (ct, ss_enc) = kem768_encapsulate(ek, [0xFFu8; 32]);
        let ss_dec = kem768_decapsulate(dk, ct);
        assert_eq!(
            ss_enc, ss_dec,
            "All-0xFF randomness keys must still satisfy ML-KEM correctness"
        );
    }

    #[test]
    fn test_alternating_bit_randomness_correctness_and_no_panic() {
        let mut rand_keygen = [0u8; 64];
        for (i, b) in rand_keygen.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xA5 } else { 0x5A };
        }
        let mut rand_encap = [0u8; 32];
        for (i, b) in rand_encap.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xC3 } else { 0x3C };
        }

        let (ek, dk) = kem768_keygen(rand_keygen);
        let (ct, ss_enc) = kem768_encapsulate(ek, rand_encap);
        let ss_dec = kem768_decapsulate(dk, ct);

        assert_eq!(
            ss_enc, ss_dec,
            "Alternating-bit randomness must satisfy correctness"
        );
    }

    #[test]
    fn test_zero_randomness_keys_differ_from_max_randomness_keys() {
        // Degenerate entropy values must still produce different key material.
        let (ek_zero, dk_zero) = kem768_keygen([0x00u8; 64]);
        let (ek_max, dk_max) = kem768_keygen([0xFFu8; 64]);

        assert_ne!(ek_zero, ek_max, "Zero and max-entropy EKs must differ");
        assert_ne!(dk_zero, dk_max, "Zero and max-entropy DKs must differ");
    }

    // ── Group 12: Overhead documentation ─────────────────────────────────────

    #[test]
    fn test_key_exchange_overhead_vs_classical_ecdh() {
        // Classical ECDH-P256 reference (RFC 8446 TLS 1.3):
        //   Ephemeral public key (uncompressed): 65 bytes
        //   Key exchange message (ciphertext):   65 bytes
        //   Shared secret:                       32 bytes
        let ecdh_pk_size: usize = 65;
        let ecdh_ct_size: usize = 65;
        let ecdh_ss_size: usize = 32;

        let (ek, dk) = kem768_keygen(KEYGEN_RAND_A);
        let (ct, ss) = kem768_encapsulate(ek, ENCAP_RAND_1);
        let _ = kem768_decapsulate(dk, ct);

        println!("=== ML-KEM-768 vs ECDH-P256 Handshake Bandwidth ===");
        println!(
            "Encapsulation key (EK):  {:5} B  │  ECDH PK:   {:3} B  │  {:2}x overhead",
            EK_SIZE,
            ecdh_pk_size,
            EK_SIZE / ecdh_pk_size
        );
        println!(
            "Ciphertext (CT):         {:5} B  │  ECDH CT:   {:3} B  │  {:2}x overhead",
            CT_SIZE,
            ecdh_ct_size,
            CT_SIZE / ecdh_ct_size
        );
        println!(
            "Decapsulation key (DK):  {:5} B  │  ECDH SK:   {:3} B",
            DK_SIZE, 32
        );
        println!(
            "Shared secret:              {:2} B  │  ECDH SS:    {:2} B  │  equivalent",
            ss.len(),
            ecdh_ss_size
        );
        println!(
            "Total wire overhead (EK+CT): {} B  │  Classical: {} B  │  {}x",
            EK_SIZE + CT_SIZE,
            ecdh_pk_size + ecdh_ct_size,
            (EK_SIZE + CT_SIZE) / (ecdh_pk_size + ecdh_ct_size)
        );
        println!("Security basis: Module-LWE (FIPS 203, NIST Category 3 — AES-192 equivalent)");
        println!(
            "Threat addressed: harvest-now-decrypt-later (HNDL) attacks on recorded P2P traffic"
        );

        // Self-consistency assertions
        assert_eq!(ss.len(), 32);
        assert_eq!(ct.len(), CT_SIZE);
        assert_eq!(ek.len(), EK_SIZE);
        assert!(
            EK_SIZE + CT_SIZE < 4096,
            "Total handshake payload must fit inside a single QUIC datagram"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Add to src/crypto/mod.rs:
//   pub mod slh_dsa;
//   pub mod lb_vrf;
//   pub mod pq_ssle;
//   pub mod zk_stark;
// ─────────────────────────────────────────────────────────────────────────────

// ═════════════════════════════════════════════════════════════════════════════
//  SLH-DSA-128s  (FIPS 205)
//  Hash-based stateless signature — validator long-lived identity / registration
//
//  Expected API (src/crypto/slh_dsa.rs):
//    pub const SLH_DSA_PK_SIZE:  usize = 32;
//    pub const SLH_DSA_SK_SIZE:  usize = 64;
//    pub const SLH_DSA_SIG_SIZE: usize = 7856;
//
//    pub fn slh_dsa_128s_keygen(seed: [u8; 48])
//        -> ([u8; SLH_DSA_PK_SIZE], [u8; SLH_DSA_SK_SIZE]);
//
//    pub fn slh_dsa_128s_sign(
//        sk:  &[u8; SLH_DSA_SK_SIZE],
//        msg: &[u8],
//        ctx: Option<&[u8]>,
//    ) -> [u8; SLH_DSA_SIG_SIZE];
//
//    pub fn slh_dsa_128s_verify(
//        pk:  &[u8; SLH_DSA_PK_SIZE],
//        msg: &[u8],
//        sig: &[u8; SLH_DSA_SIG_SIZE],
//        ctx: Option<&[u8]>,
//    ) -> bool;
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod slh_dsa_128s_tests {
    use crate::crypto::slh_dsa::{
        SLH_DSA_PK_SIZE, SLH_DSA_SIG_SIZE, SLH_DSA_SK_SIZE, slh_dsa_128s_keygen, slh_dsa_128s_sign,
        slh_dsa_128s_verify,
    };

    // ── Fixed seeds for reproducible tests ───────────────────────────────────
    // FIPS 205: keygen seed = SK.seed(n) || SK.prf(n) || PK.seed(n) = 3n = 48 bytes (n=16)
    const SEED_A: [u8; 48] = [0x11u8; 48];
    const SEED_B: [u8; 48] = [0x22u8; 48];
    const SEED_C: [u8; 48] = [0x33u8; 48];

    fn make_keypair(seed: [u8; 48]) -> ([u8; SLH_DSA_PK_SIZE], [u8; SLH_DSA_SK_SIZE]) {
        slh_dsa_128s_keygen(seed)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 1: FIPS 205 key and signature size constants
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pk_size_matches_fips205_slh_dsa_128s() {
        // FIPS 205 Table 1 — SLH-DSA-128s: PKBytes = 2n = 2×16 = 32
        assert_eq!(
            SLH_DSA_PK_SIZE, 32,
            "SLH-DSA-128s public key must be exactly 32 bytes (FIPS 205)"
        );
        let (pk, _sk) = make_keypair(SEED_A);
        assert_eq!(pk.len(), SLH_DSA_PK_SIZE);
    }

    #[test]
    fn test_sk_size_matches_fips205_slh_dsa_128s() {
        // FIPS 205 Table 1 — SLH-DSA-128s: SKBytes = 4n = 4×16 = 64
        assert_eq!(
            SLH_DSA_SK_SIZE, 64,
            "SLH-DSA-128s secret key must be exactly 64 bytes (FIPS 205)"
        );
        let (_pk, sk) = make_keypair(SEED_A);
        assert_eq!(sk.len(), SLH_DSA_SK_SIZE);
    }

    #[test]
    fn test_sig_size_matches_fips205_slh_dsa_128s() {
        // FIPS 205 Table 1 — SLH-DSA-128s (n=16, h=63, d=7, k=14, a=12, w=16):
        // SigBytes = n + k(a+1)n + d·len·n + h·n = 16 + 14·13·16 + 7·35·16 + 63·16
        //          = 16 + 2912 + 3920 + 1008 = 7856
        assert_eq!(
            SLH_DSA_SIG_SIZE, 7856,
            "SLH-DSA-128s signature must be exactly 7856 bytes (FIPS 205)"
        );
        let (_pk, sk) = make_keypair(SEED_A);
        let sig = slh_dsa_128s_sign(&sk, b"test", None);
        assert_eq!(sig.len(), SLH_DSA_SIG_SIZE);
    }

    #[test]
    fn test_sig_size_is_constant_regardless_of_message_size() {
        // SLH-DSA signature size is fixed — it does NOT grow with message size.
        // This is a key advantage over hash-then-sign schemes.
        let (_pk, sk) = make_keypair(SEED_A);

        let sig_empty = slh_dsa_128s_sign(&sk, b"", None);
        let sig_small = slh_dsa_128s_sign(&sk, b"validator-registration", None);
        let sig_medium = slh_dsa_128s_sign(&sk, &vec![0xABu8; 4096], None);
        let sig_large = slh_dsa_128s_sign(&sk, &vec![0xCDu8; 1024 * 1024], None);

        assert_eq!(
            sig_empty.len(),
            SLH_DSA_SIG_SIZE,
            "Empty message: sig must be {SLH_DSA_SIG_SIZE} B"
        );
        assert_eq!(
            sig_small.len(),
            SLH_DSA_SIG_SIZE,
            "Small message: sig must be {SLH_DSA_SIG_SIZE} B"
        );
        assert_eq!(
            sig_medium.len(),
            SLH_DSA_SIG_SIZE,
            "4KB message: sig must be {SLH_DSA_SIG_SIZE} B"
        );
        assert_eq!(
            sig_large.len(),
            SLH_DSA_SIG_SIZE,
            "1MB message: sig must be {SLH_DSA_SIG_SIZE} B"
        );

        println!(
            "✓ SLH-DSA-128s signature size constant at {SLH_DSA_SIG_SIZE} B (hash-based, stateless)"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 2: Correctness
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"validator-registration:did:huxplex:0xdeadbeef";
        let ctx = b"huxplex-mainnet:validator:registration:v1";

        let sig = slh_dsa_128s_sign(&sk, msg, Some(ctx));
        assert!(
            slh_dsa_128s_verify(&pk, msg, &sig, Some(ctx)),
            "Valid signature must verify"
        );
    }

    #[test]
    fn test_sign_and_verify_without_context() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"test message";

        let sig = slh_dsa_128s_sign(&sk, msg, None);
        assert!(
            slh_dsa_128s_verify(&pk, msg, &sig, None),
            "Context-free signature must verify without context"
        );
    }

    #[test]
    fn test_empty_message_sign_and_verify() {
        let (pk, sk) = make_keypair(SEED_A);
        let sig = slh_dsa_128s_sign(&sk, b"", None);
        assert!(
            slh_dsa_128s_verify(&pk, b"", &sig, None),
            "Empty message must be signable and verifiable"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 3: Tamper detection
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tampered_message_fails_verification() {
        let (pk, sk) = make_keypair(SEED_A);
        let original = b"Register validator: did:huxplex:0xAABBCCDD";
        let tampered = b"Register validator: did:huxplex:0xFFFFFFFF";
        let ctx = b"huxplex-mainnet:validator:registration:v1";

        let sig = slh_dsa_128s_sign(&sk, original, Some(ctx));
        assert!(
            !slh_dsa_128s_verify(&pk, tampered, &sig, Some(ctx)),
            "Tampered message must fail SLH-DSA-128s verification"
        );
    }

    #[test]
    fn test_first_byte_flip_in_signature_fails_verification() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"validator-registration";
        let mut sig = slh_dsa_128s_sign(&sk, msg, None);

        sig[0] ^= 0x01;
        assert!(
            !slh_dsa_128s_verify(&pk, msg, &sig, None),
            "First-byte flip in SLH-DSA-128s signature must fail"
        );
    }

    #[test]
    fn test_last_byte_flip_in_signature_fails_verification() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"validator-registration";
        let mut sig = slh_dsa_128s_sign(&sk, msg, None);

        sig[SLH_DSA_SIG_SIZE - 1] ^= 0xFF;
        assert!(
            !slh_dsa_128s_verify(&pk, msg, &sig, None),
            "Last-byte flip in SLH-DSA-128s signature must fail"
        );
    }

    #[test]
    fn test_middle_byte_flip_in_signature_fails_verification() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"validator-registration";
        let mut sig = slh_dsa_128s_sign(&sk, msg, None);

        sig[SLH_DSA_SIG_SIZE / 2] ^= 0xAA;
        assert!(
            !slh_dsa_128s_verify(&pk, msg, &sig, None),
            "Middle-byte flip in SLH-DSA-128s signature must fail"
        );
    }

    #[test]
    fn test_all_zero_signature_fails_verification() {
        let (pk, _sk) = make_keypair(SEED_A);
        let msg = b"validator-registration";
        let zeroed_sig = [0u8; SLH_DSA_SIG_SIZE];

        assert!(
            !slh_dsa_128s_verify(&pk, msg, &zeroed_sig, None),
            "All-zero SLH-DSA-128s signature must fail verification"
        );
    }

    #[test]
    fn test_wrong_public_key_fails_verification() {
        let (pk_a, sk_a) = make_keypair(SEED_A);
        let (pk_b, _sk_b) = make_keypair(SEED_B);
        let msg = b"validator-registration";

        let sig = slh_dsa_128s_sign(&sk_a, msg, None);

        assert!(
            slh_dsa_128s_verify(&pk_a, msg, &sig, None),
            "Correct key must verify"
        );
        assert!(
            !slh_dsa_128s_verify(&pk_b, msg, &sig, None),
            "Wrong public key must fail SLH-DSA-128s verification"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 4: Context binding
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_wrong_context_fails_verification() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"validator-registration";
        let ctx_reg = b"huxplex-mainnet:validator:registration:v1";
        let ctx_tx = b"huxplex-mainnet:tx:v1";

        let sig = slh_dsa_128s_sign(&sk, msg, Some(ctx_reg));

        assert!(
            slh_dsa_128s_verify(&pk, msg, &sig, Some(ctx_reg)),
            "Registration context must verify"
        );
        assert!(
            !slh_dsa_128s_verify(&pk, msg, &sig, Some(ctx_tx)),
            "Wrong context must fail SLH-DSA-128s verification"
        );
        assert!(
            !slh_dsa_128s_verify(&pk, msg, &sig, None),
            "Missing context must fail SLH-DSA-128s verification"
        );
    }

    #[test]
    fn test_no_context_sig_fails_when_context_required_at_verify() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"validator-registration";

        let sig = slh_dsa_128s_sign(&sk, msg, None);
        assert!(
            !slh_dsa_128s_verify(
                &pk,
                msg,
                &sig,
                Some(b"huxplex-mainnet:validator:registration:v1")
            ),
            "Context-free sig must not verify when context is required"
        );
    }

    #[test]
    fn test_mainnet_and_testnet_registration_contexts_are_domain_separated() {
        let (pk, sk) = make_keypair(SEED_A);
        let msg = b"validator-registration";
        let mainnet_ctx = b"huxplex-mainnet:validator:registration:v1";
        let testnet_ctx = b"huxplex-testnet:validator:registration:v1";

        let sig = slh_dsa_128s_sign(&sk, msg, Some(mainnet_ctx));
        assert!(
            !slh_dsa_128s_verify(&pk, msg, &sig, Some(testnet_ctx)),
            "Mainnet registration sig must not verify on testnet"
        );

        println!("✓ SLH-DSA-128s mainnet/testnet context separation enforced");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 5: Key determinism and separation
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_keygen_is_deterministic_same_seed_same_keys() {
        let (pk1, sk1) = make_keypair(SEED_A);
        let (pk2, sk2) = make_keypair(SEED_A);

        assert_eq!(pk1, pk2, "Same seed must produce identical PKs");
        assert_eq!(sk1, sk2, "Same seed must produce identical SKs");
    }

    #[test]
    fn test_different_seeds_produce_different_keys() {
        let (pk_a, sk_a) = make_keypair(SEED_A);
        let (pk_b, sk_b) = make_keypair(SEED_B);
        let (pk_c, sk_c) = make_keypair(SEED_C);

        assert_ne!(pk_a, pk_b);
        assert_ne!(pk_a, pk_c);
        assert_ne!(pk_b, pk_c);
        assert_ne!(sk_a, sk_b);
        assert_ne!(sk_a, sk_c);
    }

    #[test]
    fn test_keys_are_non_trivial() {
        let (pk, sk) = make_keypair(SEED_A);
        assert_ne!(pk, [0u8; SLH_DSA_PK_SIZE], "PK must not be all-zero");
        assert_ne!(pk, [0xFFu8; SLH_DSA_PK_SIZE], "PK must not be all-0xFF");
        assert_ne!(sk, [0u8; SLH_DSA_SK_SIZE], "SK must not be all-zero");
        assert_ne!(sk, [0xFFu8; SLH_DSA_SK_SIZE], "SK must not be all-0xFF");
    }

    #[test]
    fn test_sig_is_non_trivial() {
        let (_pk, sk) = make_keypair(SEED_A);
        let sig = slh_dsa_128s_sign(&sk, b"test", None);
        assert_ne!(
            sig, [0u8; SLH_DSA_SIG_SIZE],
            "Signature must not be all-zero"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 6: Security property — hash-only, no algebraic structure
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_slh_dsa_pk_size_distinct_from_ml_dsa_and_kem_key_sizes() {
        // SLH-DSA-128s PK (32 B) must not collide in size with:
        //   ML-DSA-44 PK (1312 B), ML-DSA-44 SK (2560 B),
        //   ML-KEM-768 EK (1184 B), ML-KEM-768 DK (2400 B)
        // This guards against type confusion at the key management layer.
        assert_ne!(
            SLH_DSA_PK_SIZE, 1312,
            "SLH-DSA PK size must differ from ML-DSA-44 PK"
        );
        assert_ne!(
            SLH_DSA_PK_SIZE, 1184,
            "SLH-DSA PK size must differ from ML-KEM-768 EK"
        );
        assert_ne!(
            SLH_DSA_SK_SIZE, 2560,
            "SLH-DSA SK size must differ from ML-DSA-44 SK"
        );
        assert_ne!(
            SLH_DSA_SK_SIZE, 2400,
            "SLH-DSA SK size must differ from ML-KEM-768 DK"
        );
        assert_ne!(
            SLH_DSA_SIG_SIZE, 2420,
            "SLH-DSA sig size must differ from ML-DSA-44 sig"
        );

        println!(
            "✓ SLH-DSA-128s sizes (PK={} B SK={} B Sig={} B) — no collision with ML-DSA-44 or ML-KEM-768",
            SLH_DSA_PK_SIZE, SLH_DSA_SK_SIZE, SLH_DSA_SIG_SIZE
        );
    }

    #[test]
    fn test_five_validator_registration_signatures_all_verify() {
        // Simulates 5 validators registering — each signs their DID with the
        // SLH-DSA-128s long-lived identity key using the registration context.
        let ctx = b"huxplex-mainnet:validator:registration:v1";

        let validators: Vec<_> = [SEED_A, SEED_B, SEED_C, [0x44u8; 48], [0x55u8; 48]]
            .iter()
            .map(|s| make_keypair(*s))
            .collect();

        let dids: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("did:huxplex:mainnet:validator:{i}").into_bytes())
            .collect();

        for (i, ((pk, sk), did)) in validators.iter().zip(dids.iter()).enumerate() {
            let sig = slh_dsa_128s_sign(sk, did, Some(ctx));
            assert!(
                slh_dsa_128s_verify(pk, did, &sig, Some(ctx)),
                "Validator {i} registration sig must verify"
            );
        }

        println!("✓ 5-validator SLH-DSA-128s registration roundtrip complete");
    }

    #[test]
    fn test_zero_and_max_seed_no_panic_and_correctness() {
        for seed in [[0x00u8; 48], [0xFFu8; 48]] {
            let (pk, sk) = make_keypair(seed);
            assert_eq!(pk.len(), SLH_DSA_PK_SIZE);
            assert_eq!(sk.len(), SLH_DSA_SK_SIZE);
            let msg = b"degenerate seed test";
            let sig = slh_dsa_128s_sign(&sk, msg, None);
            assert!(
                slh_dsa_128s_verify(&pk, msg, &sig, None),
                "Degenerate seed keys must satisfy correctness"
            );
        }
    }

    #[test]
    fn test_overhead_vs_ml_dsa_44() {
        println!("=== SLH-DSA-128s vs ML-DSA-44 Signature Overhead ===");
        println!(
            "SLH-DSA-128s PK:  {:5} B  │  ML-DSA-44 PK:  1312 B",
            SLH_DSA_PK_SIZE
        );
        println!(
            "SLH-DSA-128s SK:  {:5} B  │  ML-DSA-44 SK:  2560 B",
            SLH_DSA_SK_SIZE
        );
        println!(
            "SLH-DSA-128s Sig: {:5} B  │  ML-DSA-44 Sig: 2420 B  │  {:.1}x larger",
            SLH_DSA_SIG_SIZE,
            SLH_DSA_SIG_SIZE as f64 / 2420.0
        );
        println!(
            "Security basis: hash-only (SHAKE-256) — immune to undiscovered algebraic attacks"
        );
        println!("Use case: validator registration only (infrequent, high-assurance)");

        assert_eq!(SLH_DSA_SIG_SIZE, 7856);
        assert_eq!(SLH_DSA_PK_SIZE, 32);
        assert_eq!(SLH_DSA_SK_SIZE, 64);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  LB-VRF  (Lattice-Based Verifiable Random Function)
//  Post-quantum leader election primitive — produces VRF output + proof.
//
//  Spec: output = 84 B, proof ≈ 5 KB, eval ≈ 3 ms, verify ≈ 1 ms
//  Security: Module-SIS + Module-LWE
//  Use case: Q-BFT epoch seed generation, leader election randomness
//
//  Expected API (src/crypto/lb_vrf.rs):
//    pub const LB_VRF_OUTPUT_SIZE: usize = 84;
//    pub const LB_VRF_PROOF_MAX:   usize = 5120;
//
//    pub fn lb_vrf_keygen(seed: [u8; 32]) -> (LbVrfPublicKey, LbVrfSecretKey);
//    pub fn lb_vrf_evaluate(sk: &LbVrfSecretKey, input: &[u8])
//        -> (LbVrfOutput, LbVrfProof);
//    pub fn lb_vrf_verify(
//        pk:     &LbVrfPublicKey,
//        input:  &[u8],
//        output: &LbVrfOutput,
//        proof:  &LbVrfProof,
//    ) -> bool;
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod lb_vrf_tests {
    use crate::crypto::lb_vrf::{
        LB_VRF_OUTPUT_SIZE, LB_VRF_PROOF_MAX, lb_vrf_evaluate, lb_vrf_keygen, lb_vrf_verify,
    };

    const SEED_A: [u8; 32] = [0x11u8; 32];
    const SEED_B: [u8; 32] = [0x22u8; 32];

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 1: Output and proof size constants
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_output_size_is_84_bytes_per_spec() {
        assert_eq!(
            LB_VRF_OUTPUT_SIZE, 84,
            "LB-VRF output must be exactly 84 bytes per Huxplex spec"
        );
        let (pk, sk) = lb_vrf_keygen(SEED_A);
        let (output, _proof) = lb_vrf_evaluate(&sk, b"epoch-seed");
        assert_eq!(output.len(), LB_VRF_OUTPUT_SIZE);
    }

    #[test]
    fn test_proof_size_is_within_5kb_spec_bound() {
        assert!(
            LB_VRF_PROOF_MAX <= 6144,
            "LB-VRF proof constant must be ≤ 6 KB (spec: ~5 KB)"
        );
        let (_pk, sk) = lb_vrf_keygen(SEED_A);
        let (_output, proof) = lb_vrf_evaluate(&sk, b"epoch-seed");
        assert!(
            proof.len() <= LB_VRF_PROOF_MAX,
            "LB-VRF proof ({} B) must not exceed LB_VRF_PROOF_MAX ({} B)",
            proof.len(),
            LB_VRF_PROOF_MAX
        );
        println!(
            "✓ LB-VRF proof size: {} B (spec: ≈5 KB, max: {} B)",
            proof.len(),
            LB_VRF_PROOF_MAX
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 2: Correctness — VRF_Verify(pk, α, β, π) = true
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluate_and_verify_roundtrip() {
        let (pk, sk) = lb_vrf_keygen(SEED_A);
        let alpha = b"epoch:42:qrng-seed:0xdeadbeef";

        let (output, proof) = lb_vrf_evaluate(&sk, alpha);
        assert!(
            lb_vrf_verify(&pk, alpha, &output, &proof),
            "VRF_Verify(pk, α, β, π) must return true for a valid evaluation"
        );
    }

    #[test]
    fn test_output_is_non_trivial() {
        let (_pk, sk) = lb_vrf_keygen(SEED_A);
        let (output, _) = lb_vrf_evaluate(&sk, b"epoch:42");

        assert_ne!(
            output.as_slice(),
            &[0u8; 84][..],
            "LB-VRF output must not be all-zero"
        );
        assert_ne!(
            output.as_slice(),
            &[0xFFu8; 84][..],
            "LB-VRF output must not be all-0xFF"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 3: Determinism — VRF is a function, same inputs → same outputs
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluate_is_deterministic_same_sk_same_alpha() {
        let (_pk, sk) = lb_vrf_keygen(SEED_A);
        let alpha = b"epoch:42:qrng-seed";

        let (out1, proof1) = lb_vrf_evaluate(&sk, alpha);
        let (out2, proof2) = lb_vrf_evaluate(&sk, alpha);

        assert_eq!(
            out1, out2,
            "LB-VRF must be deterministic: same (SK, α) → same output"
        );
        assert_eq!(
            proof1, proof2,
            "LB-VRF must be deterministic: same (SK, α) → same proof"
        );
    }

    #[test]
    fn test_keygen_is_deterministic() {
        let (pk1, sk1) = lb_vrf_keygen(SEED_A);
        let (pk2, sk2) = lb_vrf_keygen(SEED_A);

        assert_eq!(pk1, pk2, "Same seed must produce identical VRF public keys");
        assert_eq!(sk1, sk2, "Same seed must produce identical VRF secret keys");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 4: Uniqueness — different inputs → different outputs
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_different_alpha_produces_different_output() {
        let (_pk, sk) = lb_vrf_keygen(SEED_A);

        let (out1, _) = lb_vrf_evaluate(&sk, b"epoch:1");
        let (out2, _) = lb_vrf_evaluate(&sk, b"epoch:2");

        assert_ne!(
            out1, out2,
            "Different inputs must produce different LB-VRF outputs"
        );
    }

    #[test]
    fn test_different_keys_produce_different_outputs_for_same_alpha() {
        let (_pk_a, sk_a) = lb_vrf_keygen(SEED_A);
        let (_pk_b, sk_b) = lb_vrf_keygen(SEED_B);
        let alpha = b"epoch:42:leader-election";

        let (out_a, _) = lb_vrf_evaluate(&sk_a, alpha);
        let (out_b, _) = lb_vrf_evaluate(&sk_b, alpha);

        assert_ne!(
            out_a, out_b,
            "Different VRF keys must produce different outputs for the same alpha"
        );
    }

    #[test]
    fn test_ten_validators_produce_distinct_outputs_for_same_epoch_seed() {
        // In Q-BFT, 10 validators each compute their VRF output over the same
        // epoch seed. All outputs must be distinct — each validator's slot is unique.
        let alpha = b"epoch:100:leader-election-seed";
        let outputs: Vec<_> = (0u8..10)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i;
                let (_pk, sk) = lb_vrf_keygen(seed);
                lb_vrf_evaluate(&sk, alpha).0
            })
            .collect();

        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(
                    outputs[i], outputs[j],
                    "Validators {i} and {j} must produce distinct VRF outputs"
                );
            }
        }

        println!("✓ 10-validator VRF outputs all distinct for same epoch seed");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 5: Tamper detection
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tampered_output_fails_verification() {
        let (pk, sk) = lb_vrf_keygen(SEED_A);
        let alpha = b"epoch:42";
        let (mut output, proof) = lb_vrf_evaluate(&sk, alpha);

        output.as_mut()[0] ^= 0x01;
        assert!(
            !lb_vrf_verify(&pk, alpha, &output, &proof),
            "Tampered VRF output must fail verification"
        );
    }

    #[test]
    fn test_tampered_proof_fails_verification() {
        let (pk, sk) = lb_vrf_keygen(SEED_A);
        let alpha = b"epoch:42";
        let (output, mut proof) = lb_vrf_evaluate(&sk, alpha);

        proof.as_mut()[0] ^= 0xFF;
        assert!(
            !lb_vrf_verify(&pk, alpha, &output, &proof),
            "Tampered VRF proof must fail verification"
        );
    }

    #[test]
    fn test_tampered_alpha_fails_verification() {
        let (pk, sk) = lb_vrf_keygen(SEED_A);
        let alpha_original = b"epoch:42";
        let alpha_tampered = b"epoch:99";

        let (output, proof) = lb_vrf_evaluate(&sk, alpha_original);
        assert!(
            !lb_vrf_verify(&pk, alpha_tampered, &output, &proof),
            "Tampered alpha must fail VRF verification"
        );
    }

    #[test]
    fn test_wrong_public_key_fails_verification() {
        let (pk_a, sk_a) = lb_vrf_keygen(SEED_A);
        let (pk_b, _sk_b) = lb_vrf_keygen(SEED_B);
        let alpha = b"epoch:42";

        let (output, proof) = lb_vrf_evaluate(&sk_a, alpha);

        assert!(
            lb_vrf_verify(&pk_a, alpha, &output, &proof),
            "Correct PK must verify"
        );
        assert!(
            !lb_vrf_verify(&pk_b, alpha, &output, &proof),
            "Wrong PK must fail VRF verification"
        );
    }

    #[test]
    fn test_proof_from_different_alpha_fails_verification() {
        // A validator cannot reuse a proof generated for one epoch on a different epoch.
        let (pk, sk) = lb_vrf_keygen(SEED_A);
        let alpha_1 = b"epoch:1";
        let alpha_2 = b"epoch:2";

        let (out_1, proof_1) = lb_vrf_evaluate(&sk, alpha_1);
        let (out_2, _proof_2) = lb_vrf_evaluate(&sk, alpha_2);

        // Proof from epoch 1 must not verify output from epoch 2
        assert!(
            !lb_vrf_verify(&pk, alpha_2, &out_2, &proof_1),
            "Proof from epoch 1 must not verify epoch 2 output"
        );
        // Output from epoch 1 must not verify for epoch 2 input
        assert!(
            !lb_vrf_verify(&pk, alpha_2, &out_1, &proof_1),
            "Epoch 1 (output, proof) must not verify for epoch 2 alpha"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 6: QRNG integration — VRF output as epoch seed source
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_vrf_output_usable_as_epoch_seed_non_repeating_across_epochs() {
        // The LB-VRF replaces ECDSA-VRFs for epoch randomness.
        // Each epoch's alpha is distinct, ensuring the QRNG seed is fresh.
        let (_pk, sk) = lb_vrf_keygen(SEED_A);

        let epochs: Vec<Vec<u8>> = (0u32..5)
            .map(|e| format!("epoch:{e}:seed").into_bytes())
            .collect();

        let outputs: Vec<_> = epochs
            .iter()
            .map(|alpha| lb_vrf_evaluate(&sk, alpha).0)
            .collect();

        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(
                    outputs[i], outputs[j],
                    "Epoch {i} and {j} VRF outputs must differ — fresh randomness each epoch"
                );
            }
        }

        println!("✓ LB-VRF epoch seeds are non-repeating across 5 epochs");
    }

    #[test]
    fn test_vrf_output_first_32_bytes_usable_as_shard_qrng_seed() {
        // shard_id = SHAKE-256(resource.nonce || epoch_qrng_seed)[0..2] mod NUM_SHARDS
        // The first 32 bytes of the 84-byte VRF output must be usable as a QRNG seed.
        let (_pk, sk) = lb_vrf_keygen(SEED_A);
        let (output, _) = lb_vrf_evaluate(&sk, b"epoch:42:shard-assignment");

        let qrng_seed: [u8; 32] = output.as_slice()[..32].try_into().unwrap();
        assert_ne!(
            qrng_seed, [0u8; 32],
            "QRNG seed slice from VRF output must be non-zero"
        );

        println!("✓ VRF output[0..32] usable as QRNG epoch seed for shard assignment");
    }

    #[test]
    fn test_overhead_documentation() {
        let (pk, sk) = lb_vrf_keygen(SEED_A);
        let (output, proof) = lb_vrf_evaluate(&sk, b"epoch:42");
        let _ = lb_vrf_verify(&pk, b"epoch:42", &output, &proof);

        println!("=== LB-VRF Overhead vs ECDSA-VRF ===");
        println!(
            "VRF output:       {:4} B  │  ECDSA-VRF output:  32 B  │  {:.1}x",
            output.len(),
            output.len() as f64 / 32.0
        );
        println!(
            "VRF proof:        {:4} B  │  ECDSA-VRF proof:   ~64 B  │  {:.0}x",
            proof.len(),
            proof.len() as f64 / 64.0
        );
        println!("Security: Module-SIS + Module-LWE (lattice-based, quantum-resistant)");
        println!("ECDSA-VRF security: ECDLP (broken by Shor's algorithm)");

        assert_eq!(output.len(), LB_VRF_OUTPUT_SIZE);
        assert!(proof.len() <= LB_VRF_PROOF_MAX);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  PQ-SSLE  (Post-Quantum Single Secret Leader Election)
//  LWE-based re-randomizable commitments — prevents DDoS on block proposer.
//
//  Protocol per Q-BFT spec:
//    1. Each validator: C_i = ssle_commit(sk_i, epoch_seed)
//    2. Shuffle oracle:  {C'} = ssle_shuffle({C_i}, epoch_seed)
//    3. Leader reveals:  L_i  = ssle_try_reveal(sk_i, C_j')  → Some(_) iff owned
//    4. Verify:          ssle_verify_leader(pk_i, C_j', L_i) → bool
//
//  Expected API (src/crypto/pq_ssle.rs):
//    pub fn ssle_keygen(seed: [u8; 32]) -> (SslePublicKey, SsleSecretKey);
//    pub fn ssle_commit(sk: &SsleSecretKey, epoch_seed: [u8; 32]) -> SsleCommitment;
//    pub fn ssle_shuffle(commitments: &[SsleCommitment], epoch_seed: [u8; 32])
//        -> Vec<SsleCommitment>;
//    pub fn ssle_try_reveal(sk: &SsleSecretKey, shuffled: &SsleCommitment)
//        -> Option<SsleReveal>;
//    pub fn ssle_verify_leader(
//        pk:         &SslePublicKey,
//        commitment: &SsleCommitment,
//        reveal:     &SsleReveal,
//    ) -> bool;
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod pq_ssle_tests {
    use crate::crypto::pq_ssle::{
        ssle_commit, ssle_keygen, ssle_shuffle, ssle_try_reveal, ssle_verify_leader,
    };

    const EPOCH_SEED_1: [u8; 32] = [0xAAu8; 32];
    const EPOCH_SEED_2: [u8; 32] = [0xBBu8; 32];

    fn make_validator_set(n: usize) -> Vec<_> {
        (0u8..n as u8)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i + 1;
                ssle_keygen(seed)
            })
            .collect()
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 1: Commit — commitments are deterministic and well-formed
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_commit_is_deterministic_same_sk_same_epoch_seed() {
        let (_pk, sk) = ssle_keygen([0x01u8; 32]);

        let c1 = ssle_commit(&sk, EPOCH_SEED_1);
        let c2 = ssle_commit(&sk, EPOCH_SEED_1);

        assert_eq!(
            c1, c2,
            "ssle_commit must be deterministic for same (SK, epoch_seed)"
        );
    }

    #[test]
    fn test_commit_differs_for_different_epoch_seeds() {
        let (_pk, sk) = ssle_keygen([0x01u8; 32]);

        let c1 = ssle_commit(&sk, EPOCH_SEED_1);
        let c2 = ssle_commit(&sk, EPOCH_SEED_2);

        assert_ne!(
            c1, c2,
            "Different epoch seeds must produce different SSLE commitments"
        );
    }

    #[test]
    fn test_different_validators_produce_different_commitments() {
        let validators = make_validator_set(5);
        let commitments: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();

        for i in 0..commitments.len() {
            for j in (i + 1)..commitments.len() {
                assert_ne!(
                    commitments[i], commitments[j],
                    "Validators {i} and {j} must have distinct commitments"
                );
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 2: Shuffle — commitments are re-randomized, order changed
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_shuffle_is_deterministic_same_inputs() {
        let validators = make_validator_set(5);
        let commitments: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();

        let shuffled1 = ssle_shuffle(&commitments, EPOCH_SEED_1);
        let shuffled2 = ssle_shuffle(&commitments, EPOCH_SEED_1);

        assert_eq!(
            shuffled1, shuffled2,
            "ssle_shuffle must be deterministic for same inputs"
        );
    }

    #[test]
    fn test_shuffle_preserves_count() {
        let n = 7;
        let validators = make_validator_set(n);
        let commitments: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();

        let shuffled = ssle_shuffle(&commitments, EPOCH_SEED_1);
        assert_eq!(
            shuffled.len(),
            n,
            "Shuffle must preserve the number of commitments"
        );
    }

    #[test]
    fn test_different_epoch_seeds_produce_different_shuffled_orders() {
        let validators = make_validator_set(5);
        let commitments: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();

        let shuffled_1 = ssle_shuffle(&commitments, EPOCH_SEED_1);
        let shuffled_2 = ssle_shuffle(&commitments, EPOCH_SEED_2);

        // Different epoch seeds should produce different shuffled orderings
        assert_ne!(
            shuffled_1, shuffled_2,
            "Different epoch seeds must produce different shuffle permutations"
        );
    }

    #[test]
    fn test_shuffle_with_single_validator_is_identity() {
        let (_pk, sk) = ssle_keygen([0x01u8; 32]);
        let commitment = ssle_commit(&sk, EPOCH_SEED_1);
        let shuffled = ssle_shuffle(&[commitment.clone()], EPOCH_SEED_1);

        assert_eq!(
            shuffled.len(),
            1,
            "Single-validator shuffle must have 1 result"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 3: Reveal — only the owning validator can successfully reveal
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_owning_validator_can_reveal_their_commitment() {
        // A validator who owns a commitment must be able to produce a valid reveal.
        let (pk, sk) = ssle_keygen([0x01u8; 32]);
        let commitment = ssle_commit(&sk, EPOCH_SEED_1);
        let shuffled = ssle_shuffle(&[commitment], EPOCH_SEED_1);

        let reveal = ssle_try_reveal(&sk, &shuffled[0]);
        assert!(
            reveal.is_some(),
            "Owning validator must successfully reveal their shuffled commitment"
        );
        assert!(
            ssle_verify_leader(&pk, &shuffled[0], &reveal.unwrap()),
            "Leader verification must succeed for owning validator"
        );
    }

    #[test]
    fn test_non_owning_validator_cannot_reveal_another_commitment() {
        // A Byzantine validator must not be able to claim a slot they don't own.
        let (_pk_1, sk_1) = ssle_keygen([0x01u8; 32]);
        let (_pk_2, sk_2) = ssle_keygen([0x02u8; 32]);

        let commitment_1 = ssle_commit(&sk_1, EPOCH_SEED_1);
        let shuffled = ssle_shuffle(&[commitment_1], EPOCH_SEED_1);

        // sk_2 attempts to reveal sk_1's shuffled commitment
        let reveal = ssle_try_reveal(&sk_2, &shuffled[0]);
        assert!(
            reveal.is_none(),
            "Non-owning validator must NOT produce a reveal for another's commitment"
        );
    }

    #[test]
    fn test_verify_leader_fails_for_wrong_public_key() {
        let (pk_1, sk_1) = ssle_keygen([0x01u8; 32]);
        let (pk_2, _sk_2) = ssle_keygen([0x02u8; 32]);

        let commitment = ssle_commit(&sk_1, EPOCH_SEED_1);
        let shuffled = ssle_shuffle(&[commitment], EPOCH_SEED_1);
        let reveal = ssle_try_reveal(&sk_1, &shuffled[0]).expect("Must succeed for owner");

        assert!(
            ssle_verify_leader(&pk_1, &shuffled[0], &reveal),
            "Correct PK must verify leader"
        );
        assert!(
            !ssle_verify_leader(&pk_2, &shuffled[0], &reveal),
            "Wrong PK must fail leader verification"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 4: Privacy — leader identity hidden before reveal
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_shuffled_commitments_do_not_reveal_validator_identity_before_reveal() {
        // The LWE re-randomization must ensure shuffled C' != original C.
        // An observer cannot map shuffled commitments back to validators without reveal.
        let validators = make_validator_set(4);
        let original_commitments: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();

        let shuffled = ssle_shuffle(&original_commitments, EPOCH_SEED_1);

        // After shuffle, the re-randomized commitments must differ from originals
        // (LWE re-randomization property)
        let any_unchanged = shuffled.iter().any(|sc| original_commitments.contains(sc));

        assert!(
            !any_unchanged,
            "No shuffled commitment must equal any original commitment \
             (LWE re-randomization must alter all commitments)"
        );

        println!(
            "✓ SSLE shuffled commitments are all distinct from originals (leader identity hidden)"
        );
    }

    #[test]
    fn test_four_validators_exactly_one_reveals_successfully_after_shuffle() {
        // In a Q-BFT election with 4 validators, exactly one shuffled slot
        // belongs to each validator. Each validator tries all shuffled slots —
        // each succeeds for exactly one.
        let n = 4;
        let validators = make_validator_set(n);
        let commitments: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();
        let shuffled = ssle_shuffle(&commitments, EPOCH_SEED_1);

        let mut successes_per_validator: Vec<usize> = vec![0; n];
        let mut reveals_per_slot: Vec<usize> = vec![0; n];

        for (i, (_pk, sk)) in validators.iter().enumerate() {
            for (j, slot) in shuffled.iter().enumerate() {
                if ssle_try_reveal(sk, slot).is_some() {
                    successes_per_validator[i] += 1;
                    reveals_per_slot[j] += 1;
                }
            }
        }

        // Each validator successfully reveals exactly 1 slot
        for (i, &count) in successes_per_validator.iter().enumerate() {
            assert_eq!(
                count, 1,
                "Validator {i} must successfully reveal exactly 1 shuffled slot"
            );
        }

        // Each slot is revealed by exactly 1 validator
        for (j, &count) in reveals_per_slot.iter().enumerate() {
            assert_eq!(count, 1, "Slot {j} must be owned by exactly 1 validator");
        }

        println!("✓ SSLE: 4 validators × 4 slots → each validator owns exactly 1 slot");
    }

    #[test]
    fn test_seven_validators_full_q_bft_election_simulation() {
        // n=7, f≤2 (Q-BFT tolerates ⌊(7-1)/3⌋ = 2 Byzantine faults)
        // Simulates a complete epoch leader election.
        let n = 7;
        let validators = make_validator_set(n);
        let commitments: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();
        let shuffled = ssle_shuffle(&commitments, EPOCH_SEED_1);

        // Find the leader: the validator who can reveal shuffled[0]
        // (in production, the first slot after shuffle is the proposer)
        let mut leader_idx = None;
        for (i, (_pk, sk)) in validators.iter().enumerate() {
            if let Some(reveal) = ssle_try_reveal(sk, &shuffled[0]) {
                let (pk, _) = &validators[i];
                assert!(
                    ssle_verify_leader(pk, &shuffled[0], &reveal),
                    "Leader reveal must verify"
                );
                leader_idx = Some(i);
                break;
            }
        }

        assert!(
            leader_idx.is_some(),
            "Exactly one validator must be able to reveal shuffled[0] as leader"
        );

        println!(
            "✓ Q-BFT epoch election: validator {} elected as leader (n=7, f≤2)",
            leader_idx.unwrap()
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 5: Epoch isolation — different epochs produce independent elections
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_different_epoch_seeds_elect_potentially_different_leaders() {
        // Two different epoch seeds should, in general, elect different leaders.
        // This is a probabilistic property — we test that the protocol is epoch-sensitive.
        let n = 5;
        let validators = make_validator_set(n);

        let commitments_1: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_1))
            .collect();
        let commitments_2: Vec<_> = validators
            .iter()
            .map(|(_pk, sk)| ssle_commit(sk, EPOCH_SEED_2))
            .collect();

        let shuffled_1 = ssle_shuffle(&commitments_1, EPOCH_SEED_1);
        let shuffled_2 = ssle_shuffle(&commitments_2, EPOCH_SEED_2);

        // The first shuffled commitment must differ between epochs
        assert_ne!(
            shuffled_1[0], shuffled_2[0],
            "Different epoch seeds must produce different first shuffled slots"
        );

        println!("✓ SSLE epoch isolation: epoch 1 and epoch 2 produce different leader slots");
    }

    #[test]
    fn test_validator_commitment_for_different_epochs_differs() {
        // A validator's commitment changes each epoch — prevents commitment replay.
        let (_pk, sk) = ssle_keygen([0x01u8; 32]);
        let c_epoch_1 = ssle_commit(&sk, EPOCH_SEED_1);
        let c_epoch_2 = ssle_commit(&sk, EPOCH_SEED_2);

        assert_ne!(
            c_epoch_1, c_epoch_2,
            "Same validator must produce different commitments for different epoch seeds"
        );
    }

    #[test]
    fn test_empty_validator_set_shuffle_is_empty() {
        let shuffled = ssle_shuffle(&[], EPOCH_SEED_1);
        assert!(
            shuffled.is_empty(),
            "Shuffling empty set must yield empty result"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  zk-STARK  (Zero-Knowledge Scalable Transparent ARgument of Knowledge)
//  Hash-based proof system — no trusted setup, quantum-resistant.
//  Used by L6 Intent Layer for proof-of-task-completion.
//
//  Spec: proof size 100–200 KB, hash-based security (STARK, not SNARK)
//  Public inputs: task_hash, output_hash, agent_did, vc_id
//  Private inputs: full task execution trace
//
//  Expected API (src/crypto/zk_stark.rs):
//    pub const STARK_MIN_PROOF_BYTES: usize = 100_000;
//    pub const STARK_MAX_PROOF_BYTES: usize = 200_000;
//
//    pub fn stark_prove(
//        witness:      &[u8],      // private: task execution trace
//        public_input: &[u8],      // task_hash || output_hash || agent_did || vc_id
//    ) -> Result<StarkProof, StarkError>;
//
//    pub fn stark_verify(
//        proof:        &StarkProof,
//        public_input: &[u8],
//    ) -> bool;
//
//    pub fn stark_public_input(
//        task_hash:   [u8; 32],
//        output_hash: [u8; 32],
//        agent_did:   &[u8],
//        vc_id:       &[u8],
//    ) -> Vec<u8>;
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod zk_stark_tests {
    use crate::crypto::zk_stark::{
        STARK_MAX_PROOF_BYTES, STARK_MIN_PROOF_BYTES, StarkError, stark_prove, stark_public_input,
        stark_verify,
    };

    // ── Canonical test fixtures ───────────────────────────────────────────────
    const TASK_HASH_A: [u8; 32] = [0xAAu8; 32];
    const OUTPUT_HASH_A: [u8; 32] = [0xBBu8; 32];
    const TASK_HASH_B: [u8; 32] = [0xCCu8; 32];
    const OUTPUT_HASH_B: [u8; 32] = [0xDDu8; 32];

    const AGENT_DID_A: &[u8] = b"did:huxplex:mainnet:0xdeadbeef01";
    const AGENT_DID_B: &[u8] = b"did:huxplex:mainnet:0xdeadbeef02";
    const VC_ID_A: &[u8] = b"vc:huxplex:work-visa:0xcafe0001";
    const VC_ID_B: &[u8] = b"vc:huxplex:work-visa:0xcafe0002";

    fn valid_witness_a() -> Vec<u8> {
        // Represents a minimal execution trace for task A
        let mut w = Vec::new();
        w.extend_from_slice(&TASK_HASH_A);
        w.extend_from_slice(&OUTPUT_HASH_A);
        w.extend_from_slice(b":execution-trace");
        w
    }

    fn valid_witness_b() -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&TASK_HASH_B);
        w.extend_from_slice(&OUTPUT_HASH_B);
        w.extend_from_slice(b":execution-trace");
        w
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 1: Proof size constants per spec
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_proof_size_constants_match_spec() {
        // Spec: "Proof size: ~100–200 KB (zk-STARK, no trusted setup)"
        assert_eq!(
            STARK_MIN_PROOF_BYTES, 100_000,
            "STARK_MIN_PROOF_BYTES must be 100 KB per spec"
        );
        assert_eq!(
            STARK_MAX_PROOF_BYTES, 200_000,
            "STARK_MAX_PROOF_BYTES must be 200 KB per spec"
        );
        assert!(
            STARK_MIN_PROOF_BYTES < STARK_MAX_PROOF_BYTES,
            "Min proof bound must be less than max"
        );
    }

    #[test]
    fn test_generated_proof_size_is_within_spec_bounds() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).expect("Valid witness must prove");

        assert!(
            proof.len() >= STARK_MIN_PROOF_BYTES,
            "zk-STARK proof ({} B) must be at least {} B",
            proof.len(),
            STARK_MIN_PROOF_BYTES
        );
        assert!(
            proof.len() <= STARK_MAX_PROOF_BYTES,
            "zk-STARK proof ({} B) must not exceed {} B",
            proof.len(),
            STARK_MAX_PROOF_BYTES
        );

        println!(
            "✓ zk-STARK proof size: {} KB (within {}-{} KB spec bounds)",
            proof.len() / 1000,
            STARK_MIN_PROOF_BYTES / 1000,
            STARK_MAX_PROOF_BYTES / 1000
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 2: Completeness — valid witness produces verifiable proof
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_completeness_valid_witness_produces_valid_proof() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input)
            .expect("Valid witness must produce a STARK proof");

        assert!(
            stark_verify(&proof, &pub_input),
            "STARK completeness: valid witness proof must verify"
        );
    }

    #[test]
    fn test_completeness_multiple_different_tasks_each_verify() {
        let tasks: &[([u8; 32], [u8; 32], &[u8], &[u8])] = &[
            (TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A),
            (TASK_HASH_B, OUTPUT_HASH_B, AGENT_DID_B, VC_ID_B),
        ];

        for (i, (th, oh, did, vc)) in tasks.iter().enumerate() {
            let pub_input = stark_public_input(*th, *oh, did, vc);
            let mut witness = Vec::new();
            witness.extend_from_slice(th);
            witness.extend_from_slice(oh);
            witness.extend_from_slice(b":trace");

            let proof = stark_prove(&witness, &pub_input).expect("Valid witness must prove");
            assert!(
                stark_verify(&proof, &pub_input),
                "Task {i} STARK proof must verify"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 3: Soundness — invalid/tampered inputs must fail verification
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_soundness_tampered_public_input_task_hash_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        // Tamper the task_hash in the public input
        let tampered_pub = stark_public_input(TASK_HASH_B, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered task_hash must fail verification"
        );
    }

    #[test]
    fn test_soundness_tampered_output_hash_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let tampered_pub = stark_public_input(TASK_HASH_A, OUTPUT_HASH_B, AGENT_DID_A, VC_ID_A);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered output_hash must fail verification"
        );
    }

    #[test]
    fn test_soundness_tampered_agent_did_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let tampered_pub = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_B, VC_ID_A);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered agent_did must fail verification — prevents identity fraud"
        );
    }

    #[test]
    fn test_soundness_tampered_vc_id_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let tampered_pub = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_B);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered vc_id must fail verification"
        );
    }

    #[test]
    fn test_soundness_first_byte_flip_in_proof_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let mut proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        proof.as_mut_bytes()[0] ^= 0x01;
        assert!(
            !stark_verify(&proof, &pub_input),
            "First-byte flip in STARK proof must fail verification"
        );
    }

    #[test]
    fn test_soundness_last_byte_flip_in_proof_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let mut proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let last = proof.len() - 1;
        proof.as_mut_bytes()[last] ^= 0xFF;
        assert!(
            !stark_verify(&proof, &pub_input),
            "Last-byte flip in STARK proof must fail verification"
        );
    }

    #[test]
    fn test_soundness_proof_a_does_not_verify_for_task_b() {
        // An agent must not reuse a proof from a previous task to claim completion of a new one.
        let pub_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_b = stark_public_input(TASK_HASH_B, OUTPUT_HASH_B, AGENT_DID_A, VC_ID_A);

        let proof_a = stark_prove(&valid_witness_a(), &pub_a).unwrap();
        let proof_b = stark_prove(&valid_witness_b(), &pub_b).unwrap();

        // Cross-proof verification must fail
        assert!(
            !stark_verify(&proof_a, &pub_b),
            "Task A proof must not verify for task B public inputs"
        );
        assert!(
            !stark_verify(&proof_b, &pub_a),
            "Task B proof must not verify for task A public inputs"
        );

        println!("✓ STARK proof binding: cross-task verification rejected");
    }

    #[test]
    fn test_soundness_empty_witness_returns_error_or_invalid_proof() {
        // An empty execution trace cannot constitute a valid proof.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let result = stark_prove(b"", &pub_input);

        match result {
            Err(StarkError::InsufficientWitness) => {
                println!("✓ Empty witness correctly rejected with InsufficientWitness error");
            }
            Ok(proof) => {
                assert!(
                    !stark_verify(&proof, &pub_input),
                    "If prove succeeds on empty witness, verify must fail"
                );
            }
            Err(e) => {
                println!("✓ Empty witness rejected with error: {:?}", e);
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 4: No trusted setup — STARK-specific properties
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_two_independent_proofs_of_same_task_both_verify() {
        // STARKs use public randomness (Fiat-Shamir). Two independently generated
        // proofs for the same (witness, public_input) should BOTH verify.
        // Unlike SNARKs, there is no per-proof trusted setup — any valid prover
        // can produce a valid proof.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let proof1 = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof2 = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        assert!(
            stark_verify(&proof1, &pub_input),
            "First STARK proof must verify"
        );
        assert!(
            stark_verify(&proof2, &pub_input),
            "Second independently generated STARK proof must verify"
        );

        println!("✓ No trusted setup: two independent proofs for same task both verify");
    }

    #[test]
    fn test_different_agents_same_task_hash_produce_different_proofs() {
        // Two different agents completing the same task (same task_hash) must produce
        // distinct proofs bound to their respective DIDs.
        let pub_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_b = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_B, VC_ID_A);

        let proof_a = stark_prove(&valid_witness_a(), &pub_a).unwrap();
        let proof_b = stark_prove(&valid_witness_a(), &pub_b).unwrap();

        // Each proof verifies for its own public input
        assert!(
            stark_verify(&proof_a, &pub_a),
            "Agent A proof must verify with Agent A DID"
        );
        assert!(
            stark_verify(&proof_b, &pub_b),
            "Agent B proof must verify with Agent B DID"
        );

        // Neither proof verifies for the other's public input
        assert!(
            !stark_verify(&proof_a, &pub_b),
            "Agent A proof must not verify with Agent B DID"
        );
        assert!(
            !stark_verify(&proof_b, &pub_a),
            "Agent B proof must not verify with Agent A DID"
        );

        println!("✓ STARK agent-DID binding: cross-agent proof reuse correctly rejected");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 5: Zero-knowledge — proof reveals nothing about the witness
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_two_proofs_of_same_statement_have_different_bytes() {
        // Fiat-Shamir randomness ensures two independently generated proofs
        // for the same (witness, public_input) are bit-distinct — an observer
        // cannot track an agent across submissions by matching proof bytes.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let proof1 = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof2 = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        assert_ne!(
            proof1.as_bytes(),
            proof2.as_bytes(),
            "Two independently generated STARK proofs must have different bytes \
             (Fiat-Shamir randomness — prevents proof-linkability)"
        );

        println!("✓ STARK proofs are not proof-linkable: two submissions differ");
    }

    #[test]
    fn test_proof_does_not_leak_witness_bytes() {
        // The proof must not contain the raw witness as a substring.
        // A zk-STARK must not embed the private execution trace in the proof.
        let witness = valid_witness_a();
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&witness, &pub_input).unwrap();

        let proof_bytes = proof.as_bytes();
        let witness_hex = hex::encode(&witness);

        // Check that the raw witness bytes do not appear verbatim in the proof
        let contains_witness = proof_bytes
            .windows(witness.len())
            .any(|w| w == witness.as_slice());

        assert!(
            !contains_witness,
            "STARK proof must not contain raw witness bytes — violates zero-knowledge property"
        );

        println!(
            "✓ STARK zero-knowledge: proof does not contain raw witness ({}-byte trace hidden)",
            witness.len()
        );
        let _ = witness_hex; // used only for debug context
    }

    #[test]
    fn test_different_witnesses_for_same_output_produce_different_proofs() {
        // Two agents arrive at the same output_hash via different execution paths.
        // Their proofs must differ — each proof commits to its own trace.
        let mut witness_alt = valid_witness_a();
        witness_alt.extend_from_slice(b":alternative-path");

        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let proof_1 = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof_2 = stark_prove(&witness_alt, &pub_input).unwrap();

        // Both must verify (same public statement)
        assert!(
            stark_verify(&proof_1, &pub_input),
            "Primary witness proof must verify"
        );
        assert!(
            stark_verify(&proof_2, &pub_input),
            "Alternative witness proof must verify"
        );

        // But they must be distinct
        assert_ne!(
            proof_1.as_bytes(),
            proof_2.as_bytes(),
            "Different witness paths must produce different proofs"
        );

        println!("✓ Different execution paths → different proofs, both valid");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 6: Work-visa / escrow integration simulation
    //
    // Spec (L6 Intent Layer):
    //   1. Agent completes task T, produces execution trace W
    //   2. Agent submits stark_prove(W, pub_input) to escrow contract
    //   3. Escrow calls stark_verify(proof, pub_input)
    //   4. On success, escrowed HUX is released to agent
    //   5. On failure, HUX is returned to requester after timeout
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_work_visa_escrow_happy_path_agent_gets_paid() {
        // Agent A completes task, submits valid proof → escrow releases payment.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input)
            .expect("Agent must be able to prove task completion");

        // Escrow verifier
        let payment_released = stark_verify(&proof, &pub_input);
        assert!(
            payment_released,
            "Escrow must release payment on valid STARK proof (work-visa happy path)"
        );

        println!("✓ Work-visa escrow: valid proof → payment released");
    }

    #[test]
    fn test_work_visa_escrow_invalid_proof_payment_withheld() {
        // Agent submits a tampered proof → escrow refuses to release payment.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let mut proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        // Agent tampers with their own proof (e.g., to claim a different output_hash)
        proof.as_mut_bytes()[42] ^= 0xFF;

        let payment_released = stark_verify(&proof, &pub_input);
        assert!(
            !payment_released,
            "Escrow must NOT release payment on tampered proof"
        );

        println!("✓ Work-visa escrow: tampered proof → payment withheld");
    }

    #[test]
    fn test_work_visa_agent_cannot_claim_another_agents_task_reward() {
        // Agent B tries to submit Agent A's valid proof to claim Agent A's reward.
        // The public input includes agent_did, so the proof is DID-bound.
        let pub_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_b = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_B, VC_ID_A);

        // Agent A legitimately proves task A
        let proof_a = stark_prove(&valid_witness_a(), &pub_a).unwrap();

        // Agent B resubmits Agent A's proof against Agent B's DID
        let payment_to_b = stark_verify(&proof_a, &pub_b);
        assert!(
            !payment_to_b,
            "Agent B must not be able to claim Agent A's reward using Agent A's proof"
        );

        println!("✓ Work-visa: cross-agent proof reuse prevented — DID binding enforced");
    }

    #[test]
    fn test_work_visa_replayed_proof_from_previous_task_rejected() {
        // An agent tries to replay a proof from task A to claim payment for task B.
        // This tests that the vc_id and task_hash are both bound into the proof.
        let pub_task_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_task_b = stark_public_input(TASK_HASH_B, OUTPUT_HASH_B, AGENT_DID_A, VC_ID_B);

        let proof_a = stark_prove(&valid_witness_a(), &pub_task_a).unwrap();

        // Attempt to use task A's proof for task B's escrow
        let payment_released = stark_verify(&proof_a, &pub_task_b);
        assert!(
            !payment_released,
            "Proof from task A must not unlock payment for task B — prevents replay across tasks"
        );

        println!("✓ Work-visa: task-replay attack prevented (task_hash + vc_id bound in proof)");
    }

    #[test]
    fn test_five_agents_five_tasks_all_complete_and_verify_independently() {
        // Simulates 5 concurrent AI agents each completing their own task.
        // This is the core L6 work-visa escrow scenario at small scale.
        let task_seeds: [(u8, u8); 5] = [
            (0x11, 0x21),
            (0x22, 0x32),
            (0x33, 0x43),
            (0x44, 0x54),
            (0x55, 0x65),
        ];

        let mut all_passed = true;
        for (i, (th_byte, oh_byte)) in task_seeds.iter().enumerate() {
            let task_hash: [u8; 32] = [*th_byte; 32];
            let output_hash: [u8; 32] = [*oh_byte; 32];
            let agent_did = format!("did:huxplex:mainnet:agent:{i}").into_bytes();
            let vc_id = format!("vc:huxplex:work-visa:{i}").into_bytes();

            let pub_input = stark_public_input(task_hash, output_hash, &agent_did, &vc_id);
            let mut witness = Vec::new();
            witness.extend_from_slice(&task_hash);
            witness.extend_from_slice(&output_hash);
            witness.extend_from_slice(b":trace");

            let proof = stark_prove(&witness, &pub_input)
                .expect("All agents must be able to prove their task");

            if !stark_verify(&proof, &pub_input) {
                all_passed = false;
                eprintln!("✗ Agent {i} task proof failed verification");
            }
        }

        assert!(all_passed, "All 5 agent task proofs must verify");
        println!("✓ 5 concurrent agent STARK proofs: all complete and verify independently");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 7: Edge cases and panic freedom
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_all_zero_public_inputs_no_panic_and_correctness() {
        // Degenerate inputs must not cause panic — must satisfy completeness.
        let pub_input =
            stark_public_input([0x00u8; 32], [0x00u8; 32], b"did:huxplex:zero", b"vc:zero");
        let mut witness = vec![0u8; 80];
        witness.extend_from_slice(b":trace");

        let result = stark_prove(&witness, &pub_input);
        match result {
            Ok(proof) => {
                // If prove succeeds on all-zero inputs, verify must also succeed
                assert!(
                    stark_verify(&proof, &pub_input),
                    "All-zero public input: prove/verify must be consistent"
                );
            }
            Err(e) => {
                println!(
                    "All-zero public inputs rejected at prove: {:?} (acceptable)",
                    e
                );
            }
        }
    }

    #[test]
    fn test_max_byte_public_inputs_no_panic_and_correctness() {
        let pub_input =
            stark_public_input([0xFFu8; 32], [0xFFu8; 32], b"did:huxplex:max", b"vc:max");
        let mut witness = vec![0xFFu8; 80];
        witness.extend_from_slice(b":trace");

        let result = stark_prove(&witness, &pub_input);
        match result {
            Ok(proof) => {
                assert!(
                    stark_verify(&proof, &pub_input),
                    "All-0xFF public input: prove/verify must be consistent"
                );
            }
            Err(e) => {
                println!("All-0xFF inputs rejected at prove: {:?} (acceptable)", e);
            }
        }
    }

    #[test]
    fn test_large_witness_no_panic_and_valid_proof_size() {
        // A large execution trace (e.g. a complex ML inference task) must still
        // produce a proof within the 100–200 KB spec bound.
        let large_witness = vec![0xABu8; 1024 * 512]; // 512 KB trace
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let result = stark_prove(&large_witness, &pub_input);
        match result {
            Ok(proof) => {
                assert!(
                    proof.len() >= STARK_MIN_PROOF_BYTES,
                    "Large-witness proof must meet minimum size"
                );
                assert!(
                    proof.len() <= STARK_MAX_PROOF_BYTES,
                    "Large-witness proof must not exceed {} B — STARK proof size is \
                     poly-logarithmic in trace length",
                    STARK_MAX_PROOF_BYTES
                );
                assert!(
                    stark_verify(&proof, &pub_input),
                    "Large-witness proof must verify"
                );
                println!(
                    "✓ 512 KB witness → {} KB proof (STARK log-size guarantee)",
                    proof.len() / 1000
                );
            }
            Err(e) => {
                println!(
                    "Large witness rejected: {:?} (acceptable if trace limit enforced)",
                    e
                );
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 8: Type separation — STARK proof must not be mistaken for
    //          SLH-DSA, ML-DSA-44 or ML-KEM ciphertexts/signatures
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_stark_proof_size_distinct_from_all_other_l1_crypto_types() {
        use crate::crypto::{
            kem::CT_SIZE,
            slh_dsa::{SLH_DSA_PK_SIZE, SLH_DSA_SIG_SIZE, SLH_DSA_SK_SIZE},
        };

        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof_len = proof.len();

        // STARK proof (100–200 KB) is orders of magnitude larger than all other types
        assert_ne!(
            proof_len, 2420,
            "STARK proof must not be same size as ML-DSA-44 sig"
        );
        assert_ne!(
            proof_len, 7856,
            "STARK proof must not be same size as SLH-DSA-128s sig"
        );
        assert_ne!(
            proof_len, CT_SIZE,
            "STARK proof must not be same size as ML-KEM-768 CT"
        );
        assert_ne!(
            proof_len, SLH_DSA_PK_SIZE,
            "STARK proof must not be same size as SLH-DSA-128s PK"
        );
        assert_ne!(
            proof_len, SLH_DSA_SK_SIZE,
            "STARK proof must not be same size as SLH-DSA-128s SK"
        );
        assert_ne!(
            proof_len, 1312,
            "STARK proof must not be same size as ML-DSA-44 PK"
        );

        println!(
            "✓ Type separation: STARK proof {} KB — no collision with ML-DSA-44 sig (2420 B), \
             SLH-DSA-128s sig (7856 B), ML-KEM-768 CT ({} B)",
            proof_len / 1000,
            CT_SIZE
        );

        let _ = (SLH_DSA_PK_SIZE, SLH_DSA_SK_SIZE, SLH_DSA_SIG_SIZE); // suppress unused warnings
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 9: Overhead documentation
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_overhead_documentation_vs_groth16_snark() {
        // zk-STARK vs Groth16 SNARK (reference: Ethereum zkEVM provers)
        //   Groth16 proof:   192 bytes  (trusted setup required)
        //   Plonk proof:     ~800 bytes (trusted setup required)
        //   zk-STARK proof:  100–200 KB (no trusted setup — transparent)
        //
        // Trade-off: larger proof, but:
        //   1. No trusted setup ceremony required
        //   2. Quantum-resistant (SHAKE-256 / FRI)
        //   3. Prover time is poly-log in trace length
        let groth16_proof_size: usize = 192;
        let plonk_proof_size: usize = 800;

        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        println!("=== zk-STARK vs Classical ZK Systems ===");
        println!(
            "zk-STARK proof:      {:>8} B  (~{} KB)",
            proof.len(),
            proof.len() / 1000
        );
        println!(
            "Groth16 (SNARK):     {:>8} B  ({:.0}x smaller, but trusted setup + not PQ)",
            groth16_proof_size,
            proof.len() as f64 / groth16_proof_size as f64
        );
        println!(
            "Plonk (SNARK):       {:>8} B  ({:.0}x smaller, but trusted setup + not PQ)",
            plonk_proof_size,
            proof.len() as f64 / plonk_proof_size as f64
        );
        println!("Trusted setup:           None  (STARK is transparent — Fiat-Shamir + FRI)");
        println!("Quantum resistance:       Yes  (security from SHAKE-256 collision resistance)");
        println!("Use case: L6 work-visa task completion / AI agent escrow settlement");

        assert!(proof.len() >= STARK_MIN_PROOF_BYTES);
        assert!(proof.len() <= STARK_MAX_PROOF_BYTES);
    }
}
