//! SLH-DSA-128s (FIPS 205) — API contract only. **Not implemented.**
//!
//! Hash-based stateless signatures, used for validator long-lived identity and
//! root-of-trust, per ADR-0002's hybrid key model (ML-DSA-44 hot signing,
//! SLH-DSA long-lived identity).
//!
//! This module exists so the conformance suite in `mod.rs` (`slh_dsa_128s_tests`)
//! type-checks against a fixed contract before there is an implementation. It is
//! `#[cfg(test)]`-only: no `unimplemented!()` cryptography is exposed in the
//! library's public API.
//!
//! Gate: **G1** (docs/16-action-plan.md). Implementing this module means making
//! `slh_dsa_128s_tests` pass and removing the `#[ignore]` markers.

/// FIPS 205 Table 1, SLH-DSA-128s: `PKBytes = 2n = 32`.
pub const SLH_DSA_PK_SIZE: usize = 32;
/// FIPS 205 Table 1, SLH-DSA-128s: `SKBytes = 4n = 64`.
pub const SLH_DSA_SK_SIZE: usize = 64;
/// FIPS 205 Table 1, SLH-DSA-128s: `SigBytes = 7856`.
pub const SLH_DSA_SIG_SIZE: usize = 7856;

const UNIMPLEMENTED: &str =
    "SLH-DSA-128s is not implemented (gate G1). See docs/16-action-plan.md.";

/// Derive a keypair from a FIPS 205 keygen seed
/// (`SK.seed(n) || SK.prf(n) || PK.seed(n)` = 3n = 48 bytes for n=16).
pub fn slh_dsa_128s_keygen(_seed: [u8; 48]) -> ([u8; SLH_DSA_PK_SIZE], [u8; SLH_DSA_SK_SIZE]) {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Sign `msg` under optional domain-separation context `ctx`.
pub fn slh_dsa_128s_sign(
    _sk: &[u8; SLH_DSA_SK_SIZE],
    _msg: &[u8],
    _ctx: Option<&[u8]>,
) -> [u8; SLH_DSA_SIG_SIZE] {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Verify `sig` over `msg` under the same context used to sign.
pub fn slh_dsa_128s_verify(
    _pk: &[u8; SLH_DSA_PK_SIZE],
    _msg: &[u8],
    _sig: &[u8; SLH_DSA_SIG_SIZE],
    _ctx: Option<&[u8]>,
) -> bool {
    unimplemented!("{UNIMPLEMENTED}")
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
    use crate::slh_dsa::{
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
    fn test_keygen_is_deterministic_same_seed_same_keys() {
        let (pk1, sk1) = make_keypair(SEED_A);
        let (pk2, sk2) = make_keypair(SEED_A);

        assert_eq!(pk1, pk2, "Same seed must produce identical PKs");
        assert_eq!(sk1, sk2, "Same seed must produce identical SKs");
    }

    #[test]
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
    fn test_keys_are_non_trivial() {
        let (pk, sk) = make_keypair(SEED_A);
        assert_ne!(pk, [0u8; SLH_DSA_PK_SIZE], "PK must not be all-zero");
        assert_ne!(pk, [0xFFu8; SLH_DSA_PK_SIZE], "PK must not be all-0xFF");
        assert_ne!(sk, [0u8; SLH_DSA_SK_SIZE], "SK must not be all-zero");
        assert_ne!(sk, [0xFFu8; SLH_DSA_SK_SIZE], "SK must not be all-0xFF");
    }

    #[test]
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
    #[ignore = "GATE: G1 — not implemented; see docs/16-action-plan.md"]
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
