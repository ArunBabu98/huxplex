//! ML-DSA-44: libcrux ↔ aws-lc-rs differential — **G1 task C11**,
//! [ADR-0019](../../../docs/adr/0019-transport-authentication.md) condition 4.
//!
//! At G5, rustls authenticates the transport with **aws-lc-rs**'s ML-DSA, while every protocol
//! signature goes through **libcrux**. Two implementations of one primitive on one network: if
//! they ever disagree on a verdict, a peer's identity and its signatures stop meaning the same
//! thing. Acceptance: *same input ⇒ identical verification verdict; cross-verification of each
//! other's signatures.* aws-lc-rs is a **dev-dependency** here; it becomes a runtime one at G5.
//!
//! aws-lc-rs signs and verifies with the **empty** FIPS 204 context only — the TLS profile. So
//! the agreement checks run at the empty context, and the last test checks the other direction
//! that matters: no Huxplex protocol signature, made under any registry context, is accepted by
//! the TLS-side verifier. That is the crypto half of **G5-T7**, established before the transport
//! exists.

#[path = "kat/parse.rs"]
mod kat;

use aws_lc_rs::{
    encoding::AsRawBytes,
    signature::{KeyPair as _, ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair, UnparsedPublicKey},
};
use hux_crypto::{
    context::{self, Network, Purpose},
    publickey::PublicKey,
    signature::{Keypair, Signature},
    signaturescheme::SignatureSchemeId,
};

const SCHEME: SignatureSchemeId = SignatureSchemeId::Dilithium2;
const EMPTY: &[u8] = b"";

fn aws_verifies(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ML_DSA_44, pk)
        .verify(message, sig)
        .is_ok()
}

fn libcrux_verifies(pk: &[u8], message: &[u8], context: &[u8], sig: &[u8]) -> bool {
    PublicKey {
        scheme: SCHEME,
        bytes: pk.to_vec(),
    }
    .verify(
        message,
        &Signature {
            scheme: SCHEME,
            bytes: sig.to_vec(),
        },
        Some(context),
    )
    .unwrap_or(false)
}

fn aws_sign(kp: &PqdsaKeyPair, message: &[u8]) -> Vec<u8> {
    let mut sig = vec![0u8; ML_DSA_44_SIGNING.signature_len()];
    let n = kp.sign(message, &mut sig).unwrap();
    sig.truncate(n);
    sig
}

#[test]
fn c11_same_seed_gives_identical_keys() {
    for i in 0u8..8 {
        let seed = [i.wrapping_mul(29).wrapping_add(3); 32];
        let ours = Keypair::generate(SCHEME, seed).unwrap();
        let theirs = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, &seed).unwrap();

        assert_eq!(ours.public_key().bytes, theirs.public_key().as_ref());
        assert_eq!(
            ours.private_key().expose_secret(),
            theirs.private_key().as_raw_bytes().unwrap().as_ref()
        );
    }
}

#[test]
fn c11_each_side_verifies_the_others_signatures() {
    let seed = [0x4Bu8; 32];
    let ours = Keypair::generate(SCHEME, seed).unwrap();
    let theirs = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, &seed).unwrap();
    let pk = ours.public_key().bytes.clone();

    for message in [&b""[..], b"m", &[0xA5u8; 4096]] {
        let our_sig = ours.sign(message, None).unwrap();
        assert!(
            aws_verifies(&pk, message, &our_sig.bytes),
            "aws-lc rejected ours"
        );

        let their_sig = aws_sign(&theirs, message);
        assert!(
            libcrux_verifies(&pk, message, EMPTY, &their_sig),
            "libcrux rejected aws-lc's"
        );
    }
}

#[test]
fn c11_verdicts_agree_on_mutations() {
    let ours = Keypair::generate(SCHEME, [0x61u8; 32]).unwrap();
    let pk = ours.public_key().bytes.clone();
    let message = b"identical verdicts";
    let sig = ours.sign(message, None).unwrap().bytes;

    let mut cases: Vec<(Vec<u8>, Vec<u8>)> = vec![(message.to_vec(), sig.clone())];
    for at in [0, 1, 1209, 2418, 2419] {
        let mut s = sig.clone();
        s[at] ^= 0x01;
        cases.push((message.to_vec(), s));
    }
    let mut m = message.to_vec();
    m[0] ^= 0x01;
    cases.push((m, sig.clone()));
    cases.push((message.to_vec(), vec![0u8; sig.len()]));

    for (i, (m, s)) in cases.iter().enumerate() {
        assert_eq!(
            libcrux_verifies(&pk, m, EMPTY, s),
            aws_verifies(&pk, m, s),
            "verdicts diverge on case {i}"
        );
    }
}

#[test]
fn c11_aws_lc_accepts_the_committed_empty_context_kat() {
    // The ML-DSA-44 fixtures were reproduced by RustCrypto ml-dsa (C10); a third implementation
    // accepting the empty-context ones closes the triangle.
    let vectors = kat::parse(include_str!("kat/ml_dsa_44.kat"));
    let mut checked = 0;
    for v in kat::of_kind(&vectors, "sign") {
        if v.get("context").is_empty() {
            assert!(aws_verifies(
                v.get("pk"),
                v.get("message"),
                v.get("signature")
            ));
            checked += 1;
        }
    }
    assert!(checked > 0, "no empty-context vector to check");
}

#[test]
fn c11_no_protocol_signature_verifies_on_the_tls_side() {
    // G5-T7, crypto half: a signature over any `huxplex-…:v1` context carries that context in its
    // FIPS 204 preimage, so aws-lc's empty-context verifier must reject it — for every registry
    // context, on both networks.
    let ours = Keypair::generate(SCHEME, [0x2Fu8; 32]).unwrap();
    let pk = ours.public_key().bytes.clone();
    let message = b"handshake transcript, or a transaction";

    for &network in Network::ALL {
        for &purpose in Purpose::ALL {
            let ctx = context::context(network, purpose);
            let sig = ours.sign(message, Some(&ctx)).unwrap();
            assert!(
                !aws_verifies(&pk, message, &sig.bytes),
                "a {} signature verified as a TLS signature",
                String::from_utf8_lossy(&ctx)
            );
        }
    }

    // And the reverse: a TLS-profile signature never verifies under a protocol context.
    let theirs = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, &[0x2Fu8; 32]).unwrap();
    let tls_sig = aws_sign(&theirs, message);
    for &purpose in Purpose::ALL {
        let ctx = context::context(Network::Mainnet, purpose);
        assert!(!libcrux_verifies(&pk, message, &ctx, &tls_sig));
    }
}
