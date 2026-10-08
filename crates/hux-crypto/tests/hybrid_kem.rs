//! X25519 + ML-KEM-768 hybrid key encapsulation — **G1 task B5**.
//!
//! G1-T5 itself (the hybrid survives a broken classical half) drives the combiner directly and
//! lives beside it in `src/kem/hybrid.rs`. These are the public-API properties: sizes, round
//! trips through the registry, tamper behaviour, low-order rejection, and the X25519 half against
//! the RFC 7748 published vector.

#[path = "kat/parse.rs"]
mod kat;

use hux_crypto::{
    error::CryptoError,
    kem::{hybrid, kem768_encapsulate, kem768_keygen, x25519},
    suite::KemId,
    traits::{self, Kem},
};

const HYBRID: &str = include_str!("kat/hybrid_x25519_ml_kem_768.kat");

fn hybrid_kem() -> &'static dyn Kem {
    traits::kem(KemId::X25519MlKem768)
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[test]
fn x25519_matches_rfc_7748_section_6_1() {
    // The published Diffie–Hellman example: checkable against an external authority, not only
    // against this project's history.
    let alice_sk: [u8; 32] =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap()
            .try_into()
            .unwrap();
    let bob_sk: [u8; 32] =
        hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .unwrap()
            .try_into()
            .unwrap();

    let alice_pk = x25519::public_key(&alice_sk);
    let bob_pk = x25519::public_key(&bob_sk);
    assert_eq!(
        hex(&alice_pk),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex(&bob_pk),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );

    let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert_eq!(
        hex(&x25519::shared_secret(&alice_sk, &bob_pk).unwrap()),
        shared
    );
    assert_eq!(
        hex(&x25519::shared_secret(&bob_sk, &alice_pk).unwrap()),
        shared
    );
}

#[test]
fn x25519_rejects_a_low_order_point() {
    // The all-zero u-coordinate is a low-order point: every scalar maps it to zero.
    assert!(matches!(
        x25519::shared_secret(&[0x42; 32], &[0u8; 32]),
        Err(CryptoError::KeyAgreementFailed(_))
    ));
}

#[test]
fn hybrid_sizes_are_the_concatenation_of_its_halves() {
    let s = hybrid_kem().sizes();
    assert_eq!(s.encapsulation_key, 1184 + 32);
    assert_eq!(s.decapsulation_key, 2400 + 32);
    assert_eq!(s.ciphertext, 1088 + 32);
    assert_eq!(s.shared_secret, 32);
    assert_eq!((s.keygen_seed, s.encaps_randomness), (96, 64));
}

#[test]
fn hybrid_round_trip_with_production_randomness() {
    let kem = hybrid_kem();
    let (ek, dk) = kem.generate(&[0x13u8; 96]).unwrap();

    let (ct1, ss1) = traits::encapsulate(kem, &ek).unwrap();
    let (ct2, ss2) = traits::encapsulate(kem, &ek).unwrap();
    assert_eq!(kem.decapsulate(&dk, &ct1).unwrap(), ss1);
    assert_eq!(kem.decapsulate(&dk, &ct2).unwrap(), ss2);
    assert_ne!(
        ss1, ss2,
        "production encapsulation must draw fresh randomness"
    );
}

#[test]
fn hybrid_secret_differs_from_the_ml_kem_secret_alone() {
    // Same ML-KEM inputs as a pure ML-KEM exchange; the hybrid secret must not equal it, or the
    // classical half contributes nothing.
    let seed = [0x21u8; 96];
    let randomness = [0x34u8; 64];
    let (ek, _) = hybrid_kem().generate(&seed).unwrap();
    let (_, hybrid_ss) = hybrid_kem().encapsulate_derand(&ek, &randomness).unwrap();

    let (ek_m, _) = kem768_keygen(seed[..64].try_into().unwrap());
    let (_, mlkem_ss) = kem768_encapsulate(ek_m, randomness[..32].try_into().unwrap());
    assert_ne!(hybrid_ss, mlkem_ss);
}

#[test]
fn tampering_with_either_half_of_the_ciphertext_changes_the_secret() {
    let kem = hybrid_kem();
    let (ek, dk) = kem.generate(&[0x55u8; 96]).unwrap();
    let (ct, ss) = kem.encapsulate_derand(&ek, &[0x66u8; 64]).unwrap();

    // ML-KEM half: implicit rejection yields a pseudorandom secret, never an error.
    let mut ct_m = ct.clone();
    ct_m[0] ^= 0x01;
    assert_ne!(kem.decapsulate(&dk, &ct_m).unwrap(), ss);

    // X25519 half: a different point gives a different secret (or a rejection if low-order).
    let mut ct_x = ct.clone();
    ct_x[1088 + 5] ^= 0x01;
    match kem.decapsulate(&dk, &ct_x) {
        Ok(other) => assert_ne!(other, ss),
        Err(e) => assert!(matches!(e, CryptoError::KeyAgreementFailed(_))),
    }
}

#[test]
fn a_low_order_x25519_share_is_rejected_not_silently_accepted() {
    let kem = hybrid_kem();
    let (ek, dk) = kem.generate(&[0x77u8; 96]).unwrap();
    let (mut ct, _) = kem.encapsulate_derand(&ek, &[0x88u8; 64]).unwrap();
    ct[1088..].fill(0);
    assert!(matches!(
        kem.decapsulate(&dk, &ct),
        Err(CryptoError::KeyAgreementFailed(_))
    ));
}

#[test]
fn wrong_lengths_are_errors_not_panics() {
    let kem = hybrid_kem();
    assert!(kem.generate(&[0u8; 64]).is_err());
    let (ek, dk) = kem.generate(&[1u8; 96]).unwrap();
    assert!(kem.encapsulate_derand(&ek[..1184], &[0u8; 64]).is_err());
    assert!(kem.encapsulate_derand(&ek, &[0u8; 32]).is_err());
    assert!(kem.decapsulate(&dk, &[0u8; 1088]).is_err());
}

#[test]
fn kat_hybrid_x25519_ml_kem_768() {
    let vectors = kat::parse(HYBRID);
    for v in kat::of_kind(&vectors, "encaps") {
        let kem = hybrid_kem();
        let (ek, dk) = kem.generate(v.get("keygen_seed")).unwrap();
        assert_eq!(hex(&ek), hex(v.get("ek")));
        assert_eq!(hex(&dk), hex(v.get("dk")));

        let (ct, ss) = kem
            .encapsulate_derand(&ek, v.get("encaps_randomness"))
            .unwrap();
        assert_eq!(hex(&ct), hex(v.get("ct")));
        assert_eq!(hex(&ss), hex(v.get("shared_secret")));
        assert_eq!(
            hex(&kem.decapsulate(&dk, &ct).unwrap()),
            hex(v.get("shared_secret"))
        );
    }
}

#[test]
fn kat_hybrid_combiner_label_is_pinned() {
    assert_eq!(hybrid::COMBINER_LABEL, b"X25519-MLKEM768-v1-COMBINE");
}
