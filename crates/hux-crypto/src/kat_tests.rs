//! Byte-exact signature KATs — **G1 task C10**, the half that needs task C9.
//!
//! Production signing is hedged and takes no caller randomness (crypto spec §3), so a pinned
//! signature can only be *reproduced* through [`Keypair::sign_with_randomness`], which exists in
//! test builds of this crate and nowhere else. That is why these vectors are checked here, as a
//! unit test, rather than in `tests/` with the rest of the KATs.

#[path = "../tests/kat/parse.rs"]
mod kat;

use crate::{signature::Keypair, signaturescheme::SignatureSchemeId};

#[test]
fn kat_ml_dsa_44_signatures_are_byte_exact() {
    let vectors = kat::parse(include_str!("../tests/kat/ml_dsa_44.kat"));
    for v in kat::of_kind(&vectors, "sign") {
        let kp = Keypair::generate(SignatureSchemeId::Dilithium2, v.array("seed")).unwrap();
        let sig = kp
            .sign_with_randomness(
                v.get("message"),
                Some(v.get("context")),
                v.get("randomness"),
            )
            .unwrap();
        assert_eq!(hex::encode(&sig.bytes), hex::encode(v.get("signature")));
    }
}

#[test]
fn kat_slh_dsa_shake_128s_signatures_are_byte_exact() {
    let vectors = kat::parse(include_str!("../tests/kat/slh_dsa_shake_128s.kat"));
    for v in kat::of_kind(&vectors, "sign") {
        let kp = Keypair::generate_from_seed(SignatureSchemeId::SlhDsa128s, v.get("seed")).unwrap();
        let sig = kp
            .sign_with_randomness(
                v.get("message"),
                Some(v.get("context")),
                v.get("randomness"),
            )
            .unwrap();
        assert_eq!(hex::encode(&sig.bytes), hex::encode(v.get("signature")));
    }
}
