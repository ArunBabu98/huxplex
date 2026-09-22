//! BIP32 -> ML-DSA seed derivation and key purposes.
//! Path: m/44'/931931'/{purpose}'/0'/{index}'  (ADR-0014, ADR-0018).
//!
//! Extracted from `lib.rs` at gate G0 (workspace migration, task W2).
//! Integration tests reach only the crate's **public API**, which is the point: an over-broad
//! `pub` shows up here immediately, and a secret field can never be widened to satisfy a test.
//!
//! See `docs/18-implementation-plan/00-workspace-migration.md`.

use hux_crypto::{
    bip32::{KeyPurpose, derive_mldsa_seed, derive_mldsa_seed_for_purpose},
    signature::Keypair,
    signaturescheme::SignatureSchemeId,
};

const HEXSEED: &str = "75ca70e0863b97e3e5cde1bc9b6eae8101158802cf7e916e7afc03f241941996dd0d391e42f36345af6079f35003270390a4a958492b5f9563fa629e89262177";

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
            kp.private_key().len(),
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
fn test_key_purposes_are_domain_separated_at_the_same_index() {
    // ADR-0018 / ADR-0019 / ADR-0021: a validator's session key, its future
    // quorum-certificate key, its identity key, its governance key and its TLS transport
    // key all derive from one master seed and MUST NOT collide at the same epoch index.
    let bytes = hex::decode(HEXSEED).expect("Must be valid hex");
    let master: [u8; 64] = bytes.as_slice().try_into().expect("Seed must be 64 bytes");

    let purposes = [
        KeyPurpose::Transaction,
        KeyPurpose::QuorumCert,
        KeyPurpose::Identity,
        KeyPurpose::Governance,
        KeyPurpose::Transport,
    ];

    for index in [0u32, 1, 7] {
        let seeds: Vec<[u8; 32]> = purposes
            .iter()
            .map(|&p| derive_mldsa_seed_for_purpose(master, p, index))
            .collect();

        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert_ne!(
                    seeds[i], seeds[j],
                    "purposes {:?} and {:?} must not collide at index {index}",
                    purposes[i], purposes[j]
                );
            }
        }
    }
    println!("✓ 5 key purposes are domain-separated at every epoch index");
}

#[test]
fn test_transaction_purpose_reproduces_the_original_path() {
    // Adding the purpose level MUST NOT change any key already derived. Purpose 0 is the
    // pre-ADR-0018 path `m/44'/931931'/0'/0'/{index}'` exactly.
    let bytes = hex::decode(HEXSEED).expect("Must be valid hex");
    let master: [u8; 64] = bytes.as_slice().try_into().expect("Seed must be 64 bytes");

    for index in [0u32, 1, 5, 10, 999] {
        assert_eq!(
            derive_mldsa_seed(master, index),
            derive_mldsa_seed_for_purpose(master, KeyPurpose::Transaction, index),
            "purpose-0 derivation must equal the original path at index {index}"
        );
    }
    println!("✓ Purpose 0 is byte-identical to the original derivation — no key changed");
}
