//! SLH-DSA-SHAKE-128s differential test against RustCrypto `slh-dsa` — **G1 task C8**.
//!
//! `fips205` is the implementation; RustCrypto `slh-dsa` is an independent one, a
//! **dev-dependency only**. Acceptance: *same seed ⇒ identical key and signature bytes; a
//! deliberate mutation fails.* Hash-based signatures are fully deterministic in
//! `(seed, message, context, opt_rand)`, so any divergence at all is a bug in one of them.

#[path = "kat/parse.rs"]
mod kat;

use hux_crypto::{
    signature::{Keypair, Signature},
    signaturescheme::SignatureSchemeId,
};
use slh_dsa::{Shake128s, SigningKey, VerifyingKey};

const SLH_DSA: &str = include_str!("kat/slh_dsa_shake_128s.kat");
const SCHEME: SignatureSchemeId = SignatureSchemeId::SlhDsa128s;

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn oracle_keygen(seed: &[u8]) -> SigningKey<Shake128s> {
    SigningKey::<Shake128s>::slh_keygen_internal(&seed[..16], &seed[16..32], &seed[32..48])
}

fn oracle_vk(pk: &[u8]) -> VerifyingKey<Shake128s> {
    VerifyingKey::<Shake128s>::try_from(pk).unwrap()
}

fn oracle_verifies(pk: &[u8], message: &[u8], context: &[u8], sig: &[u8]) -> bool {
    match slh_dsa::Signature::<Shake128s>::try_from(sig) {
        Ok(sig) => oracle_vk(pk)
            .try_verify_with_context(message, context, &sig)
            .is_ok(),
        Err(_) => false,
    }
}

#[test]
fn c8_same_seed_gives_identical_keys() {
    // The fixture seeds plus a sweep of structured ones, so agreement is not an accident of two
    // particular inputs.
    let mut seeds: Vec<Vec<u8>> = kat::parse(SLH_DSA)
        .iter()
        .map(|v| v.get("seed").to_vec())
        .collect();
    seeds.extend((0u8..6).map(|i| (0..48).map(|j| i.wrapping_mul(37) ^ j).collect()));

    for seed in seeds {
        let ours = Keypair::generate_from_seed(SCHEME, &seed).unwrap();
        let theirs = oracle_keygen(&seed);
        assert_eq!(
            hex(&ours.public_key().bytes),
            hex(&theirs.as_ref().to_bytes())
        );
        assert_eq!(
            hex(ours.private_key().expose_secret()),
            hex(&theirs.to_bytes())
        );
    }
}

#[test]
fn c8_oracle_reproduces_every_pinned_signature() {
    let vectors = kat::parse(SLH_DSA);
    for v in kat::of_kind(&vectors, "sign") {
        let sk = oracle_keygen(v.get("seed"));
        let sig = sk
            .try_sign_with_context(
                v.get("message"),
                v.get("context"),
                Some(v.get("randomness")),
            )
            .unwrap();
        assert_eq!(hex(&sig.to_bytes()), hex(v.get("signature")));
    }
}

#[test]
fn c8_each_side_verifies_the_others_production_signatures() {
    let seed = [0x77u8; 48];
    let (message, context) = (
        &b"governance:registry-update"[..],
        &b"huxplex-testnet:vc:v1"[..],
    );

    // Ours, hedged with a fresh opt_rand, verified by theirs.
    let ours = Keypair::generate_from_seed(SCHEME, &seed).unwrap();
    let our_sig = ours.sign(message, Some(context)).unwrap();
    assert!(oracle_verifies(
        &ours.public_key().bytes,
        message,
        context,
        &our_sig.bytes
    ));

    // Theirs, hedged with a different opt_rand, verified by ours.
    let theirs = oracle_keygen(&seed);
    let their_sig = theirs
        .try_sign_with_context(message, context, Some(&[0x3Cu8; 16]))
        .unwrap();
    let their_sig = Signature {
        scheme: SCHEME,
        bytes: their_sig.to_bytes().to_vec(),
    };
    assert!(
        ours.public_key()
            .verify(message, &their_sig, Some(context))
            .unwrap()
    );
}

#[test]
fn c8_a_mutation_is_rejected_by_both_implementations() {
    // The differential is only worth having if it can disagree with something. A single flipped
    // bit anywhere in a signature, message or context must fail under both verifiers.
    let v = &kat::parse(SLH_DSA)[0];
    let (pk, message, context, sig) = (
        v.get("pk"),
        v.get("message"),
        v.get("context"),
        v.get("signature"),
    );
    let ours = |m: &[u8], c: &[u8], s: &[u8]| {
        hux_crypto::publickey::PublicKey {
            scheme: SCHEME,
            bytes: pk.to_vec(),
        }
        .verify(
            m,
            &Signature {
                scheme: SCHEME,
                bytes: s.to_vec(),
            },
            Some(c),
        )
        .unwrap()
    };

    assert!(ours(message, context, sig) && oracle_verifies(pk, message, context, sig));

    for at in [0, 16, 2928, 7855] {
        let mut s = sig.to_vec();
        s[at] ^= 0x01;
        assert!(!ours(message, context, &s), "ours accepted a flip at {at}");
        assert!(
            !oracle_verifies(pk, message, context, &s),
            "oracle accepted a flip at {at}"
        );
    }

    let mut m = message.to_vec();
    m[0] ^= 0x01;
    assert!(!ours(&m, context, sig) && !oracle_verifies(pk, &m, context, sig));

    let mut c = context.to_vec();
    c[0] ^= 0x01;
    assert!(!ours(message, &c, sig) && !oracle_verifies(pk, message, &c, sig));
}
