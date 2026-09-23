//! A guided, self-verifying tour of Huxplex's Layer-0 networking envelopes.
//!
//! Run it:
//!
//! ```text
//! cargo run -p hux-network --example network_walkthrough
//! ```
//!
//! Every step prints what it is doing and then **asserts** the property it demonstrates.
//!
//! ⚠️ **There is no transport yet.** This exercises peer identity and the *signed envelopes* —
//! the cryptographic half of the network. The swarm, QUIC, TLS with ML-DSA certificates,
//! Kademlia and GossipSub arrive at gate G5
//! (`docs/18-implementation-plan/03-g5-transport.md`). What you can verify today is that
//! nothing on the wire is unauthenticated and nothing replays across a boundary.
//!
//! See `docs/19-verification/02-network.md`.

use hux_crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};
use hux_network::{
    message::{DhtEntry, GossipMessage},
    peer::PeerId,
    topic::GossipTopic,
};

fn step(n: u32, title: &str) {
    println!(
        "\n── {n}. {title} {}",
        "─".repeat(62_usize.saturating_sub(title.len()))
    );
}

fn ok(msg: &str) {
    println!("   ✓ {msg}");
}

fn kp(seed: u8) -> Keypair {
    Keypair::generate(SignatureSchemeId::Dilithium2, [seed; 32]).unwrap()
}

fn main() {
    println!("Huxplex Layer 0 — networking walkthrough");
    println!("target arch: {}", std::env::consts::ARCH);

    // ───────────────────────────────────────────────────────────────────────────────────
    step(1, "PeerId = SHAKE-256(ML-DSA-44 public key)[..32]");
    let alice = kp(0x01);
    let bob = kp(0x02);
    let alice_id = PeerId::from_ml_dsa_pk(alice.public_key().clone());
    let bob_id = PeerId::from_ml_dsa_pk(bob.public_key().clone());
    println!("   alice : {}", alice_id.to_hex());
    println!("   bob   : {}", bob_id.to_hex());
    assert_eq!(alice_id.id.len(), 32);
    assert_ne!(alice_id, bob_id);
    assert_eq!(
        alice_id,
        PeerId::from_ml_dsa_pk(alice.public_key().clone()),
        "PeerId must be deterministic"
    );
    ok("self-certifying: the identity IS the key, so no registry can revoke or forge it");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(2, "Signed gossip");
    let topic = GossipTopic::shard_blocks(0);
    let msg = GossipMessage::sign(
        &alice,
        topic.clone(),
        "mainnet",
        b"block-proposal-payload".to_vec(),
    )
    .unwrap();
    println!("   topic   : {}", msg.topic.as_str());
    println!("   network : {}", msg.network);
    println!("   sig     : {} bytes (ML-DSA-44)", msg.sig.bytes.len());
    assert!(msg.verify().unwrap());
    ok("every gossip message carries its own signature — relays cannot mint traffic");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(3, "Topic tampering is rejected");
    let mut moved = GossipMessage::sign(
        &alice,
        GossipTopic::shard_blocks(0),
        "mainnet",
        b"payload".to_vec(),
    )
    .unwrap();
    moved.topic = GossipTopic::shard_mempool(0);
    assert!(!moved.verify().unwrap());
    ok("a blocks-topic signature does not verify on the mempool topic");

    let mut cross_shard = GossipMessage::sign(
        &alice,
        GossipTopic::shard_blocks(0),
        "mainnet",
        b"payload".to_vec(),
    )
    .unwrap();
    cross_shard.topic = GossipTopic::shard_blocks(1);
    assert!(!cross_shard.verify().unwrap());
    ok("a shard-0 signature does not verify on shard 1 — no cross-shard leakage");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(4, "Cross-network replay is rejected");
    let mut replayed = GossipMessage::sign(
        &alice,
        GossipTopic::intents(),
        "mainnet",
        b"intent".to_vec(),
    )
    .unwrap();
    replayed.network = "testnet".to_string();
    assert!(!replayed.verify().unwrap());
    ok("a mainnet gossip message cannot be replayed on testnet");

    let mut dht_replay = DhtEntry::sign(
        &alice,
        alice_id.id.to_vec(),
        b"10.0.0.1:30333".to_vec(),
        "mainnet",
    )
    .unwrap();
    assert!(dht_replay.verify().unwrap());
    dht_replay.network = "testnet".to_string();
    assert!(!dht_replay.verify().unwrap());
    ok("nor can a mainnet DHT record");
    println!("     (this one was untestable until 2026-09-22 — the DHT context was");
    println!("      hard-coded to `mainnet`, so the property could not be exercised)");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(5, "DHT route poisoning is rejected");
    let honest = DhtEntry::sign(
        &alice,
        alice_id.id.to_vec(),
        b"10.0.0.1:30333".to_vec(),
        "mainnet",
    )
    .unwrap();
    assert!(honest.verify().unwrap());

    let mut hijacked = DhtEntry::sign(
        &alice,
        alice_id.id.to_vec(),
        b"10.0.0.1:30333".to_vec(),
        "mainnet",
    )
    .unwrap();
    hijacked.value = b"666.666.666.666:1".to_vec();
    assert!(!hijacked.verify().unwrap());
    ok("rewriting a peer's advertised address invalidates the record");

    let mut swapped = DhtEntry::sign(
        &alice,
        alice_id.id.to_vec(),
        b"10.0.0.1:30333".to_vec(),
        "mainnet",
    )
    .unwrap();
    swapped.signer_pk = bob.public_key().clone();
    assert!(!swapped.verify().unwrap());
    ok("substituting the signer's public key invalidates it too");

    // ───────────────────────────────────────────────────────────────────────────────────
    step(6, "Identity is consistent end to end");
    let node = kp(0xAA);
    let node_id = PeerId::from_ml_dsa_pk(node.public_key().clone());
    let announcement = DhtEntry::sign(
        &node,
        node_id.id.to_vec(),
        b"192.168.1.10:30333".to_vec(),
        "mainnet",
    )
    .unwrap();
    let broadcast = GossipMessage::sign(
        &node,
        GossipTopic::shard_blocks(0),
        "mainnet",
        b"genesis".to_vec(),
    )
    .unwrap();
    assert_eq!(
        node_id,
        PeerId::from_ml_dsa_pk(announcement.signer_pk.clone())
    );
    assert_eq!(node_id, PeerId::from_ml_dsa_pk(broadcast.from.clone()));
    ok("one key drives PeerId, the DHT announcement and the gossip sender — no impersonation gap");

    // ───────────────────────────────────────────────────────────────────────────────────
    println!("\n{}", "═".repeat(72));
    println!(
        "All Layer-0 networking envelope invariants held on {}.",
        std::env::consts::ARCH
    );
    println!("Not yet covered (gate G5): QUIC transport, TLS with ML-DSA certificates,");
    println!("live Kademlia, GossipSub scoring, peer state machine.");
    println!("{}", "═".repeat(72));
}
