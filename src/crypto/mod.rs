mod bip32;
mod error;
mod kem;
mod privatekey;
mod publickey;
mod signature;
mod signaturescheme;

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
}

#[cfg(test)]
mod ml_kem_768_tests {
    use crate::crypto::kem::*;

    // ── Fixed randomness for reproducible tests ──────────────────────────────
    const KEYGEN_RAND_A: [u8; 64] = [0x11u8; 64];
    const ENCAP_RAND_1: [u8; 32] = [0xAAu8; 32];

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
}
