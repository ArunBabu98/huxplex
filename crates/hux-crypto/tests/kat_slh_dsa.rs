//! Byte-exact known-answer tests for SLH-DSA-SHAKE-128s — **G1 tasks C7, C10**, **G1-T3**.
//!
//! Public-API half: keygen from the 48-byte seed and verification of the pinned signatures,
//! through the registry exactly as a downstream crate reaches it. Reproducing the signatures needs
//! the pinned `opt_rand`, which only the crate's test-only entry point accepts — that half is
//! `src/kat_tests.rs`. RustCrypto `slh-dsa` reproducing every vector is
//! `tests/slh_dsa_differential.rs`.

#[path = "kat/parse.rs"]
mod kat;

use hux_crypto::{
    signature::{Keypair, Signature},
    signaturescheme::SignatureSchemeId,
    suite::{AlgoSuite, SigRole, SuiteVersion},
};

const SLH_DSA: &str = include_str!("kat/slh_dsa_shake_128s.kat");

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn scheme() -> SignatureSchemeId {
    // Reached through the Identity role's v1 row, not by naming the scheme — the same path a
    // validator-registration verifier takes.
    AlgoSuite::new(SigRole::Identity, SuiteVersion::V1)
        .signature_scheme()
        .unwrap()
}

#[test]
fn kat_slh_dsa_keygen_from_seed() {
    let vectors = kat::parse(SLH_DSA);
    for v in kat::of_kind(&vectors, "sign") {
        let kp = Keypair::generate_from_seed(scheme(), v.get("seed")).unwrap();
        assert_eq!(hex(&kp.public_key().bytes), hex(v.get("pk")));
        assert_eq!(hex(kp.private_key().expose_secret()), hex(v.get("sk")));
    }
}

#[test]
fn kat_slh_dsa_pinned_signatures_verify_and_bind_their_inputs() {
    let vectors = kat::parse(SLH_DSA);
    for v in kat::of_kind(&vectors, "sign") {
        let kp = Keypair::generate_from_seed(scheme(), v.get("seed")).unwrap();
        let pk = kp.public_key();
        let sig = Signature {
            scheme: scheme(),
            bytes: v.get("signature").to_vec(),
        };
        let (message, context) = (v.get("message"), v.get("context"));

        assert!(pk.verify(message, &sig, Some(context)).unwrap());

        let mut other_message = message.to_vec();
        other_message.push(0);
        assert!(!pk.verify(&other_message, &sig, Some(context)).unwrap());
        assert!(
            !pk.verify(message, &sig, Some(b"huxplex-mainnet:vc:v1"))
                .unwrap()
        );
    }
}

#[test]
fn slh_dsa_keypair_refuses_a_32_byte_seed() {
    // `Keypair::generate` takes the 32 bytes BIP32 yields; SLH-DSA's seed is 3n = 48. The
    // registry must refuse rather than stretch, pad or truncate — inventing a derivation here
    // would be an unspecified consensus decision taken by accident.
    assert!(Keypair::generate(scheme(), [0u8; 32]).is_err());
}

#[test]
fn slh_dsa_production_signing_round_trips_through_the_registry() {
    let kp = Keypair::generate_from_seed(scheme(), &[0x5Au8; 48]).unwrap();
    let ctx = b"huxplex-testnet:validator:registration:v1";
    let sig = kp
        .sign(b"did:huxplex:testnet:validator:0", Some(ctx))
        .unwrap();
    assert_eq!(sig.bytes.len(), 7856);
    assert!(
        kp.public_key()
            .verify(b"did:huxplex:testnet:validator:0", &sig, Some(ctx))
            .unwrap()
    );
}
