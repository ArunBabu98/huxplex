//! A guided, self-verifying tour of Huxplex's Layer-0 cryptography.
//!
//! Run it:
//!
//! ```text
//! cargo run -p hux-crypto --example crypto_walkthrough
//! ```
//!
//! Every step prints what it is doing and then **asserts** the property it is demonstrating,
//! so the program is simultaneously a demo and a test. If it prints the final banner, the
//! invariants held on your machine, on your architecture.
//!
//! See `docs/19-verification/01-crypto.md` for what each step is proving and why it matters.

use hux_crypto::{
    bip32::{KeyPurpose, derive_mldsa_seed, derive_mldsa_seed_for_purpose},
    kem::{kem768_decapsulate, kem768_derive_session_key, kem768_encapsulate, kem768_keygen},
    signature::Keypair,
    signaturescheme::SignatureSchemeId,
};

const MASTER_SEED_HEX: &str = "75ca70e0863b97e3e5cde1bc9b6eae8101158802cf7e916e7afc03f241941996\
dd0d391e42f36345af6079f35003270390a4a958492b5f9563fa629e89262177";

fn step(n: u32, title: &str) {
    println!(
        "\n── {n}. {title} {}",
        "─".repeat(64_usize.saturating_sub(title.len()))
    );
}

fn ok(msg: &str) {
    println!("   ✓ {msg}");
}

fn main() {
    println!("Huxplex Layer 0 — cryptography walkthrough");
    println!("target arch: {}", std::env::consts::ARCH);

    let master: [u8; 64] = hex::decode(MASTER_SEED_HEX)
        .expect("valid hex")
        .try_into()
        .expect("64 bytes");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(1, "Deterministic key generation (ML-DSA-44, FIPS 204)");
    let kp = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let kp_again = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    println!("   public key : {} bytes", kp.public_key().bytes.len());
    println!("   secret key : {} bytes", kp.private_key().len());
    assert_eq!(kp.public_key().bytes.len(), 1312, "FIPS 204 pk size");
    assert_eq!(kp.private_key().len(), 2560, "FIPS 204 sk size");
    assert_eq!(kp.public_key().bytes, kp_again.public_key().bytes);
    ok("same seed ⇒ same key, and sizes match FIPS 204");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(2, "Secret hygiene — Debug must never print key material");
    let rendered = format!("{:?}", kp.private_key());
    println!("   {rendered}");
    assert!(rendered.contains("redacted"), "Debug must redact");
    assert!(
        !rendered.contains(&hex::encode(&kp.private_key().expose_secret()[..8])),
        "Debug leaked key bytes"
    );
    ok("a stray `dbg!` or log line cannot exfiltrate a signing key");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(3, "HD derivation and key purposes (ADR-0014, ADR-0018)");
    println!("   path: m/44'/931931'/{{purpose}}'/0'/{{index}}'");
    let purposes = [
        ("Transaction", KeyPurpose::Transaction),
        ("QuorumCert ", KeyPurpose::QuorumCert),
        ("Identity   ", KeyPurpose::Identity),
        ("Governance ", KeyPurpose::Governance),
        ("Transport  ", KeyPurpose::Transport),
    ];
    let mut seen = Vec::new();
    for (name, p) in purposes {
        let seed = derive_mldsa_seed_for_purpose(master, p, 0);
        println!(
            "   {name} (purpose {}) → {}…",
            p.index(),
            hex::encode(&seed[..8])
        );
        assert!(!seen.contains(&seed), "purpose collision");
        seen.push(seed);
    }
    assert_eq!(
        derive_mldsa_seed(master, 0),
        derive_mldsa_seed_for_purpose(master, KeyPurpose::Transaction, 0),
        "purpose 0 must reproduce the original path"
    );
    ok("five purposes, no collisions; purpose 0 is byte-identical to the pre-purpose path");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(4, "Sign / verify, and hedged (randomized) signing");
    let msg = b"a Huxplex transaction";
    let ctx = b"huxplex-mainnet:tx:v1";
    let sig_a = kp.sign(msg, Some(ctx)).unwrap();
    let sig_b = kp.sign(msg, Some(ctx)).unwrap();
    println!("   signature  : {} bytes", sig_a.bytes.len());
    assert_eq!(sig_a.bytes.len(), 2420, "FIPS 204 sig size");
    assert_ne!(
        sig_a.bytes, sig_b.bytes,
        "hedged signing must not be deterministic"
    );
    assert!(kp.public_key().verify(msg, &sig_a, Some(ctx)).unwrap());
    assert!(kp.public_key().verify(msg, &sig_b, Some(ctx)).unwrap());
    ok("two signatures over the same message differ, and both verify");
    println!("     (deterministic lattice signing + fault injection is a key-recovery path —");
    println!("      eprint 2025/2009 — so randomness per signature is mandatory, not optional)");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(5, "Tamper detection");
    let mut bad_msg = msg.to_vec();
    bad_msg[0] ^= 0x01;
    assert!(!kp.public_key().verify(&bad_msg, &sig_a, Some(ctx)).unwrap());
    ok("one flipped bit in the message ⇒ rejected");

    let mut bad_sig = sig_a.clone();
    bad_sig.bytes[100] ^= 0x01;
    assert!(!kp.public_key().verify(msg, &bad_sig, Some(ctx)).unwrap());
    ok("one flipped bit in the signature ⇒ rejected");

    let other = Keypair::generate(SignatureSchemeId::Dilithium2, [2u8; 32]).unwrap();
    assert!(!other.public_key().verify(msg, &sig_a, Some(ctx)).unwrap());
    ok("a different public key ⇒ rejected");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(
        6,
        "Domain separation — the cheapest high-leverage defence we have",
    );
    let contexts: [&[u8]; 5] = [
        b"huxplex-mainnet:tx:v1",
        b"huxplex-testnet:tx:v1",
        b"huxplex-mainnet:block:prepare:v1",
        b"huxplex-mainnet:block:commit:v1",
        b"huxplex-mainnet:dht:entry:v1",
    ];
    for signing_ctx in contexts {
        let s = kp.sign(msg, Some(signing_ctx)).unwrap();
        for verify_ctx in contexts {
            let accepted = kp.public_key().verify(msg, &s, Some(verify_ctx)).unwrap();
            let same = signing_ctx == verify_ctx;
            assert_eq!(accepted, same, "context separation broken");
        }
    }
    println!(
        "   swept all {}×{} context pairs",
        contexts.len(),
        contexts.len()
    );
    ok("a signature verifies under its own context and no other —");
    println!("     mainnet ≠ testnet, prepare ≠ commit, tx ≠ dht. Replay across purposes is dead.");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(
        7,
        "ML-KEM-768 key encapsulation (FIPS 203) and directional session keys",
    );
    let (ek, dk) = kem768_keygen([7u8; 64]);
    let (ct, ss_sender) = kem768_encapsulate(ek, [9u8; 32]);
    let ss_receiver = kem768_decapsulate(dk, ct);
    println!(
        "   encaps key {} B · ciphertext {} B · shared secret {} B",
        ek.len(),
        ct.len(),
        ss_sender.len()
    );
    assert_eq!(
        ss_sender, ss_receiver,
        "both sides must agree on the shared secret"
    );
    ok("encapsulate/decapsulate agree");

    let a = [0xAAu8; 32];
    let b = [0xBBu8; 32];
    let k_ab = kem768_derive_session_key(ss_sender, a, b, None, Some(b"handshake"));
    let k_ba = kem768_derive_session_key(ss_sender, b, a, None, Some(b"handshake"));
    assert_ne!(k_ab, k_ba, "derivation must be directional");
    ok("A→B and B→A session keys differ — reflection attacks cannot reuse a key");

    // ───────────────────────────────────────────────────────────────────────────────────
    println!("\n{}", "═".repeat(72));
    println!(
        "All Layer-0 cryptographic invariants held on {}.",
        std::env::consts::ARCH
    );
    println!("Next: cargo run -p hux-network --example network_walkthrough");
    println!("{}", "═".repeat(72));
}
