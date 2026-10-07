//! An independent implementation reproduces every committed KAT — **G1 task C10**.
//!
//! The vectors in `tests/kat/` were generated from libcrux. On their own they would prove only
//! that libcrux agrees with its own history, which is what a migration needs but not what a
//! *conformance* fixture needs. Here RustCrypto's `ml-dsa` and `ml-kem` — a separate codebase
//! by separate authors, a **dev-dependency only** — rebuild every vector from its inputs. A
//! fixture both reproduce is FIPS 204 / FIPS 203 output, not one vendor's.
//!
//! Signing goes through the oracle's `sign_internal` with the FIPS 204 §5.2 external-message
//! framing written out (`0x00 ‖ len(ctx) ‖ ctx ‖ M`), so the pinned `rnd` reaches the signature
//! exactly as it does through libcrux.

#![allow(deprecated)] // `to_expanded*`: the expanded secret-key encoding is what we store.

#[path = "kat/parse.rs"]
mod kat;

use ml_dsa::{KeyExport as _, Keypair as _, MlDsa44, SigningKey};
use ml_kem::{Decapsulate, ExpandedKeyEncoding, ml_kem_768::DecapsulationKey};

const ML_DSA_44: &str = include_str!("kat/ml_dsa_44.kat");
const ML_KEM_768: &str = include_str!("kat/ml_kem_768.kat");

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[test]
fn differential_ml_dsa_44_keygen() {
    let vectors = kat::parse(ML_DSA_44);
    for v in vectors.iter() {
        let seed: [u8; 32] = v.array("seed");
        let kp = SigningKey::<MlDsa44>::from_seed(&seed.into());
        assert_eq!(hex(&kp.verifying_key().to_bytes()), hex(v.get("pk")));
        assert_eq!(hex(&kp.expanded_key().to_expanded()), hex(v.get("sk")));
    }
}

#[test]
fn differential_ml_dsa_44_signatures() {
    let vectors = kat::parse(ML_DSA_44);
    for v in kat::of_kind(&vectors, "sign") {
        let seed: [u8; 32] = v.array("seed");
        let rnd: [u8; 32] = v.array("randomness");
        let (message, context) = (v.get("message"), v.get("context"));
        let kp = SigningKey::<MlDsa44>::from_seed(&seed.into());

        let framed: [&[u8]; 4] = [&[0], &[context.len() as u8], context, message];
        let sig = kp.expanded_key().sign_internal(&framed, &rnd.into());
        assert_eq!(hex(&sig.encode()), hex(v.get("signature")));

        assert!(
            kp.verifying_key()
                .verify_with_context(message, context, &sig)
        );
    }
}

#[test]
fn differential_ml_kem_768() {
    let vectors = kat::parse(ML_KEM_768);
    for v in kat::of_kind(&vectors, "encaps") {
        let d_z: [u8; 64] = v.array("keygen_randomness");
        let m: [u8; 32] = v.array("encaps_randomness");
        let dk = DecapsulationKey::from_seed(d_z.into());
        let ek = dk.encapsulation_key();

        assert_eq!(hex(&ek.to_bytes()), hex(v.get("ek")));
        assert_eq!(hex(&dk.to_expanded_bytes()), hex(v.get("dk")));

        let (ct, ss) = ek.encapsulate_deterministic(&m.into());
        assert_eq!(hex(&ct), hex(v.get("ct")));
        assert_eq!(hex(&ss), hex(v.get("shared_secret")));
        assert_eq!(hex(&dk.decapsulate(&ct)), hex(v.get("shared_secret")));
    }
}
