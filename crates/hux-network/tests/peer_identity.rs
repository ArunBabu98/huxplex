//! PeerId derivation: `PeerId = SHAKE-256(ML-DSA-44 public key)[..32]`.
//!
//! Extracted from `lib.rs` at gate G0 (workspace migration, task W2). Integration tests reach
//! only the public API of `hux-network` and `hux-crypto`.
//!
//! See `docs/18-implementation-plan/00-workspace-migration.md`.

use hux_crypto::{
    kem::{EK_SIZE, kem768_keygen},
    signature::Keypair,
    signaturescheme::SignatureSchemeId,
};
use hux_network::peer::PeerId;

fn make_keypair(seed: u8) -> Keypair {
    Keypair::generate(SignatureSchemeId::Dilithium2, [seed; 32]).unwrap()
}

// ══════════════════════════════════════════════════════════════════════════
// GROUP 1: PeerId derivation
// peer_id = SHAKE-256(ml_dsa44_public_key_bytes)[0..32]
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_peer_id_is_32_bytes() {
    let kp = make_keypair(0x01);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    assert_eq!(
        pid.id.len(),
        32,
        "PeerId must be exactly 32 bytes (SHAKE-256 output)"
    );
}

#[test]
fn test_peer_id_is_deterministic_from_same_key() {
    let kp = make_keypair(0x01);
    let pid1 = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let pid2 = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    assert_eq!(
        pid1, pid2,
        "Same ML-DSA-44 key must always produce the same PeerId"
    );
}

#[test]
fn test_peer_id_is_non_trivial() {
    let kp = make_keypair(0x01);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    assert_ne!(pid.id, [0u8; 32], "PeerId must never be all-zero");
    assert_ne!(pid.id, [0xFFu8; 32], "PeerId must never be all-0xFF");
}

#[test]
fn test_different_ml_dsa_keys_produce_different_peer_ids() {
    let kp1 = make_keypair(0x01);
    let kp2 = make_keypair(0x02);
    let pid1 = PeerId::from_ml_dsa_pk(kp1.public_key().clone());
    let pid2 = PeerId::from_ml_dsa_pk(kp2.public_key().clone());
    assert_ne!(
        pid1, pid2,
        "Different ML-DSA-44 keys must produce different PeerIds"
    );
}

#[test]
fn test_five_validator_peer_ids_are_all_distinct() {
    let pids: Vec<PeerId> = (1u8..=5)
        .map(|i| PeerId::from_ml_dsa_pk(make_keypair(i).public_key().clone()))
        .collect();

    for i in 0..pids.len() {
        for j in (i + 1)..pids.len() {
            assert_ne!(
                pids[i], pids[j],
                "Validator PeerIds {i} and {j} must be distinct"
            );
        }
    }
    println!("✓ 5 validator PeerIds — all distinct");
}

#[test]
fn test_peer_id_does_not_equal_ml_kem_key_fingerprint() {
    // PeerId is derived from ML-DSA-44 PK (identity/auth key).
    // ML-KEM-768 EK is the session KEM key (different role).
    // They must not produce the same 32-byte fingerprint.
    let kp = make_keypair(0x01);
    let (kem_ek, _) = kem768_keygen([0x01u8; 64]);
    let dsa_pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());

    // ML-KEM EK is 1184 bytes, ML-DSA PK is 1312 bytes — sizes differ entirely
    assert_ne!(
        kp.public_key().bytes.len(),
        EK_SIZE,
        "ML-DSA-44 PK size must differ from ML-KEM-768 EK size"
    );
    // The peer ID bytes must not accidentally equal the first 32 bytes of the KEM EK
    assert_ne!(
        dsa_pid.id,
        kem_ek[..32],
        "PeerId must not collide with the ML-KEM EK prefix"
    );
}

#[test]
fn test_peer_id_hex_display_is_lowercase_64_chars() {
    let kp = make_keypair(0x42);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let hex = pid.to_hex();
    assert_eq!(hex.len(), 64, "PeerId hex must be 64 characters (32 bytes)");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "PeerId hex must only contain hex digits"
    );
    assert!(
        hex.chars().all(|c| !c.is_uppercase()),
        "PeerId hex must be lowercase"
    );
}
