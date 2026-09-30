//! Byte-exact known-answer tests for the deterministic primitives — **G1 task C10, in part**.
//!
//! # Why these exist, and why they exist *now*
//!
//! C10 asks for byte-exact KAT fixtures across ML-DSA-44, ML-KEM-768, SLH-DSA-128s and the hash
//! domains, and was recorded as blocked on **C9** (splitting deterministic signing). That
//! dependency was drawn too broadly: **C9 blocks *signature* KATs**, because a signature needs
//! pinned randomness to be reproducible. Hashes and KDFs take no randomness at all, so their
//! vectors are committable today — and they are the half needed to prove a hash-crate migration
//! changes nothing.
//!
//! These vectors were generated from the **previous** implementation (RustCrypto `sha3` 0.10 /
//! `hkdf` 0.12 + `sha2` 0.10) and must continue to hold. That direction matters: a KAT generated
//! from the new implementation would prove only that the new code agrees with itself.
//!
//! # What each vector protects
//!
//! `PeerId = SHAKE-256(ML-DSA-44 pk)[..32]` is **peer identity** — the Kademlia routing key, the
//! GossipSub scoring key and the DHT record key. A single byte changing here is a network-wide
//! identity change, not a refactor. `kem768_derive_session_key` is every transport session key.
//! Both are exactly the kind of value that is easy to change by accident and impossible to change
//! safely once a network exists.
//!
//! Remaining for full C10: ML-DSA-44 and ML-KEM-768 vectors (keygen is deterministic and could
//! land now; *signature* vectors need C9), SLH-DSA-128s (C7), and BLAKE3 (G2b).

use hux_crypto::{hash::shake::shake256_32, kem::kem768_derive_session_key};

/// Lowercase hex, so a failure prints the actual bytes rather than an array debug dump —
/// a KAT that fails unreadably costs more than it saves.
fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ─── SHAKE-256 ───────────────────────────────────────────────────────────────────────────────

#[test]
fn kat_shake256_empty_input_matches_the_published_fips202_value() {
    // The one vector here that is checkable against an external authority rather than against
    // our own history: SHAKE256("") is published, and any correct implementation reproduces it.
    // If this fails, the primitive is wrong — not merely different from what we had.
    assert_eq!(
        hex(&shake256_32(b"")),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
}

#[test]
fn kat_shake256_short_inputs() {
    assert_eq!(
        hex(&shake256_32(b"abc")),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    );
    assert_eq!(
        hex(&shake256_32(b"huxplex")),
        "6d9fb8d5fd97fde8b776a7f6cad956053304c7722c201d4694295cf945e04bd4"
    );
}

#[test]
fn kat_shake256_at_ml_dsa_44_public_key_length() {
    // 1312 bytes is the ML-DSA-44 verification-key size, i.e. the *only* input length that
    // actually occurs when deriving a PeerId. Absorbing a multi-block input is where a sponge
    // implementation differs if it is going to, so these are the load-bearing vectors.
    assert_eq!(
        hex(&shake256_32(&[0x00u8; 1312])),
        "0028adcd941e9a739a27cad3086c6e53706efad66be73c58b0ca7852a0c87331"
    );
    assert_eq!(
        hex(&shake256_32(&[0xFFu8; 1312])),
        "36d659af58af574d6945d8f36a392f874cee96d42257c044b4faaf2a42186840"
    );

    let patterned: Vec<u8> = (0..1312).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        hex(&shake256_32(&patterned)),
        "91b1a31e785a0a148ccdc7f3af5c1dbbb2265db2a7e694fd2998880acff2e002"
    );
}

#[test]
fn kat_shake256_output_length_is_a_type_parameter_not_a_read_count() {
    use hux_crypto::hash::shake::shake256;

    // A 32-byte squeeze must be a prefix of a longer one — the sponge property — and, more
    // practically, the length cannot be short-changed at runtime the way an incremental
    // `Read`-based squeeze could be.
    let long = shake256::<64>(b"huxplex");
    assert_eq!(shake256_32(b"huxplex")[..], long[..32]);
}

// ─── HKDF-SHA-256 session keys ───────────────────────────────────────────────────────────────

const SS: [u8; 32] = [0u8; 32];

#[test]
fn kat_session_key_no_salt_no_label() {
    assert_eq!(
        hex(&kem768_derive_session_key(
            SS, [1u8; 32], [2u8; 32], None, None
        )),
        "ea214e929bb453a40ba576b8ee3825654ca7018d950fa05ac24c531308980836"
    );
}

#[test]
fn kat_session_key_with_salt_and_protocol_label() {
    assert_eq!(
        hex(&kem768_derive_session_key(
            [0xABu8; 32],
            [0x01u8; 32],
            [0x02u8; 32],
            Some(b"huxplex-salt"),
            Some(b"huxplex-mainnet"),
        )),
        "19c942e55ea63887d6ab2450fe5db07a9c73c96ce1ca916e35b18935dea54a4f"
    );
}

#[test]
fn kat_session_key_is_direction_asymmetric() {
    // Both vectors pinned, and asserted distinct. The derivation binds (peer_a, peer_b) in order,
    // so the two directions of one session must not collide — a property the existing suite tests
    // behaviourally and this pins byte-exactly.
    let ab = kem768_derive_session_key([7u8; 32], [9u8; 32], [0x0Au8; 32], None, Some(b"dir"));
    let ba = kem768_derive_session_key([7u8; 32], [0x0Au8; 32], [9u8; 32], None, Some(b"dir"));

    assert_eq!(
        hex(&ab),
        "6c3277037458d53dc0f3b96890ac81288e62a947c977941c2d89aa0727e9c180"
    );
    assert_eq!(
        hex(&ba),
        "66c987da7c5b45e96eb907c36725fef061d42cebd4cb4b595e4fdf60e4290935"
    );
    assert_ne!(
        ab, ba,
        "direction asymmetry is the point of binding peer order"
    );
}
