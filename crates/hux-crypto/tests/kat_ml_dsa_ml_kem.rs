//! Byte-exact known-answer tests for ML-DSA-44 and ML-KEM-768 — **G1 task C10**, **G1-T3**.
//!
//! Fixtures live in `tests/kat/*.kat`; their headers record the crate versions they came from.
//! These tests reach only the public API, so they cover everything a downstream crate can
//! reproduce: keygen (deterministic in its seed), BIP32 → keygen, verification of the pinned
//! signatures, and the whole KEM round trip.
//!
//! *Producing* the pinned signatures needs the nonce chosen, which only the crate's test-only
//! entry point allows (task C9) — that half is `src/kat_tests.rs`. An independent implementation
//! reproducing every vector is `tests/kat_differential.rs`.
//!
//! G1-T3 asks for these on **both architectures**; CI runs this file on x86-64, aarch64 Linux and
//! aarch64 Darwin, so a backend that disagreed would fail here rather than fork the network.

#[path = "kat/parse.rs"]
mod kat;

use hux_crypto::{
    bip32::derive_mldsa_seed,
    kem::{kem768_decapsulate, kem768_encapsulate, kem768_keygen},
    signature::{Keypair, Signature},
    signaturescheme::SignatureSchemeId,
};

const ML_DSA_44: &str = include_str!("kat/ml_dsa_44.kat");
const ML_KEM_768: &str = include_str!("kat/ml_kem_768.kat");

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ─── ML-DSA-44 ───────────────────────────────────────────────────────────────────────────────

#[test]
fn kat_ml_dsa_44_bip32_keygen_crypto_spec_7_1() {
    let vectors = kat::parse(ML_DSA_44);
    for v in kat::of_kind(&vectors, "keygen-bip32") {
        let index = u32::from_be_bytes(v.array("index"));
        let seed = derive_mldsa_seed(v.array("master_seed"), index);
        assert_eq!(hex(&seed), hex(v.get("seed")), "BIP32 seed derivation");

        let kp = Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap();
        assert_eq!(hex(&kp.public_key().bytes), hex(v.get("pk")));
        assert_eq!(hex(kp.private_key().expose_secret()), hex(v.get("sk")));
    }
}

#[test]
fn kat_ml_dsa_44_keygen_from_seed() {
    let vectors = kat::parse(ML_DSA_44);
    for v in kat::of_kind(&vectors, "sign") {
        let kp = Keypair::generate(SignatureSchemeId::Dilithium2, v.array("seed")).unwrap();
        assert_eq!(hex(&kp.public_key().bytes), hex(v.get("pk")));
        assert_eq!(hex(kp.private_key().expose_secret()), hex(v.get("sk")));
    }
}

#[test]
fn kat_ml_dsa_44_pinned_signatures_verify_and_bind_their_inputs() {
    let vectors = kat::parse(ML_DSA_44);
    for v in kat::of_kind(&vectors, "sign") {
        let kp = Keypair::generate(SignatureSchemeId::Dilithium2, v.array("seed")).unwrap();
        let pk = kp.public_key();
        let sig = Signature {
            scheme: SignatureSchemeId::Dilithium2,
            bytes: v.get("signature").to_vec(),
        };
        let (message, context) = (v.get("message"), v.get("context"));

        assert!(pk.verify(message, &sig, Some(context)).unwrap());

        // A KAT that only checks "verifies" would pass for any valid signature; these confirm the
        // fixture is bound to exactly its message and context.
        let mut other_message = message.to_vec();
        other_message.push(0);
        assert!(!pk.verify(&other_message, &sig, Some(context)).unwrap());
        assert!(
            !pk.verify(message, &sig, Some(b"huxplex-mainnet:other:v1"))
                .unwrap()
        );
    }
}

// ─── ML-KEM-768 ──────────────────────────────────────────────────────────────────────────────

#[test]
fn kat_ml_kem_768_keygen_encapsulate_decapsulate() {
    let vectors = kat::parse(ML_KEM_768);
    for v in kat::of_kind(&vectors, "encaps") {
        let (ek, dk) = kem768_keygen(v.array("keygen_randomness"));
        assert_eq!(hex(&ek), hex(v.get("ek")));
        assert_eq!(hex(&dk), hex(v.get("dk")));

        let (ct, ss) = kem768_encapsulate(ek, v.array("encaps_randomness"));
        assert_eq!(hex(&ct), hex(v.get("ct")));
        assert_eq!(hex(&ss), hex(v.get("shared_secret")));

        assert_eq!(
            hex(&kem768_decapsulate(dk, ct)),
            hex(v.get("shared_secret"))
        );
    }
}
