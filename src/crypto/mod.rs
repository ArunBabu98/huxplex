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
