//! Signed gossip and DHT envelopes: authentication, tamper rejection,
//! cross-network and cross-shard replay rejection, and the end-to-end identity pipeline.
//!
//! Extracted from `lib.rs` at gate G0 (workspace migration, task W2). Integration tests reach
//! only the public API of `hux-network` and `hux-crypto`.
//!
//! See `docs/18-implementation-plan/00-workspace-migration.md`.

use hux_crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};
use hux_network::{
    message::{DhtEntry, GossipMessage},
    peer::PeerId,
    topic::{GossipTopic, gossip_context},
};

fn make_keypair(seed: u8) -> Keypair {
    Keypair::generate(SignatureSchemeId::Dilithium2, [seed; 32]).unwrap()
}

#[test]
fn test_dht_entry_sign_and_verify_roundtrip() {
    let kp = make_keypair(0x10);
    let peer_id = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let value = b"127.0.0.1:30333".to_vec();

    let entry = DhtEntry::sign(&kp, peer_id.id.to_vec(), value, "mainnet").unwrap();
    assert!(entry.verify().unwrap(), "Valid DHT entry must verify");
}

#[test]
fn test_dht_entry_tampered_value_fails_verification() {
    let kp = make_keypair(0x10);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let mut entry =
        DhtEntry::sign(&kp, pid.id.to_vec(), b"127.0.0.1:30333".to_vec(), "mainnet").unwrap();

    // Attacker changes the routing value (IP/port)
    entry.value = b"1.2.3.4:9999".to_vec();
    assert!(
        !entry.verify().unwrap(),
        "Tampered DHT value must fail verification"
    );
}

#[test]
fn test_dht_entry_tampered_key_fails_verification() {
    let kp = make_keypair(0x10);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let mut entry =
        DhtEntry::sign(&kp, pid.id.to_vec(), b"127.0.0.1:30333".to_vec(), "mainnet").unwrap();

    // Attacker changes the DHT key (peer routing table poisoning attempt)
    entry.key[0] ^= 0xFF;
    assert!(
        !entry.verify().unwrap(),
        "Tampered DHT key must fail verification"
    );
}

#[test]
fn test_dht_entry_wrong_signer_fails_verification() {
    let kp1 = make_keypair(0x10);
    let kp2 = make_keypair(0x11);
    let pid = PeerId::from_ml_dsa_pk(kp1.public_key().clone());
    let mut entry = DhtEntry::sign(
        &kp1,
        pid.id.to_vec(),
        b"127.0.0.1:30333".to_vec(),
        "mainnet",
    )
    .unwrap();

    // Route poisoning: attacker swaps in their own public key
    entry.signer_pk = kp2.public_key().clone();
    assert!(
        !entry.verify().unwrap(),
        "Wrong signer public key must fail DHT entry verification"
    );
}

#[test]
fn test_dht_entry_cross_network_replay_fails() {
    // Crypto spec §5.1: a mainnet signature must not verify under a testnet context.
    // Previously untestable — `dht:entry` was hard-coded to mainnet in the primitive.
    let kp = make_keypair(0x10);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let value = b"127.0.0.1:30333".to_vec();

    let mut entry = DhtEntry::sign(&kp, pid.id.to_vec(), value, "mainnet").unwrap();
    assert!(entry.verify().unwrap());

    // Replay the mainnet record on testnet.
    entry.network = "testnet".to_string();
    assert!(
        !entry.verify().unwrap(),
        "A mainnet DHT entry must not verify under the testnet context"
    );
}

#[test]
fn test_dht_entry_key_matches_peer_id_of_signing_key() {
    // Best practice: the DHT key should be the peer's own PeerId.
    // This test verifies the binding is consistent.
    let kp = make_keypair(0x10);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let entry =
        DhtEntry::sign(&kp, pid.id.to_vec(), b"127.0.0.1:30333".to_vec(), "mainnet").unwrap();

    assert_eq!(
        entry.key,
        pid.id.to_vec(),
        "DHT key must match the PeerId derived from the signing ML-DSA-44 key"
    );
    assert!(entry.verify().unwrap());
}

//     // ══════════════════════════════════════════════════════════════════════════
//     // GROUP 6: Cross-layer integration
//     // PeerId → GossipMessage → DHT entry binding
//     // ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_full_node_identity_pipeline() {
    // Simulates a new node joining the network:
    // 1. Generates ML-DSA-44 identity keypair
    // 2. Derives PeerId from it
    // 3. Publishes a DHT entry announcing its address
    // 4. Signs and broadcasts a gossip message on a shard topic

    let kp = make_keypair(0xAA);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());

    // Step 3: DHT announcement
    let dht = DhtEntry::sign(&kp, pid.id.to_vec(), b"10.0.0.1:30333".to_vec(), "mainnet").unwrap();
    assert!(dht.verify().unwrap(), "Node DHT announcement must be valid");

    // Step 4: Gossip broadcast
    let msg = GossipMessage::sign(
        &kp,
        GossipTopic::shard_blocks(0),
        "mainnet",
        b"genesis-block-hash".to_vec(),
    )
    .unwrap();
    assert!(msg.verify().unwrap(), "Node gossip broadcast must be valid");

    // Peer ID consistency: the same ML-DSA-44 key drives both
    let pid_from_dht_signer = PeerId::from_ml_dsa_pk(dht.signer_pk);
    assert_eq!(
        pid, pid_from_dht_signer,
        "DHT signer PeerId must match node PeerId"
    );

    let pid_from_msg_sender = PeerId::from_ml_dsa_pk(msg.from);
    assert_eq!(
        pid, pid_from_msg_sender,
        "Gossip sender PeerId must match node PeerId"
    );

    println!("✓ Full node identity pipeline: keygen → PeerId → DHT → GossipMessage");
}

#[test]
fn test_ten_validators_each_with_unique_peer_id_and_valid_dht_entries() {
    // Simulates 10 validators in a Q-BFT set.
    // Each must have a unique PeerId and valid authenticated DHT presence.
    let validators: Vec<_> = (1u8..=10)
        .map(|i| {
            let kp = make_keypair(i);
            let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
            let dht = DhtEntry::sign(
                &kp,
                pid.id.to_vec(),
                format!("192.168.1.{}:30333", i).into_bytes(),
                "mainnet",
            )
            .unwrap();
            (pid, dht)
        })
        .collect();

    // All PeerIds distinct
    for i in 0..validators.len() {
        for j in (i + 1)..validators.len() {
            assert_ne!(
                validators[i].0, validators[j].0,
                "Validators {i} and {j} must have distinct PeerIds"
            );
        }
    }

    // All DHT entries valid
    for (i, (_, dht)) in validators.iter().enumerate() {
        assert!(
            dht.verify().unwrap(),
            "Validator {i} DHT entry must be valid"
        );
    }

    println!("✓ 10-validator set: all PeerIds unique, all DHT entries authenticated");
}

#[test]
fn test_cross_shard_gossip_messages_use_different_contexts() {
    // A validator proposing on shard 0 must use a different context than shard 1.
    // Tests that no shard can accidentally validate another shard's messages.
    let kp = make_keypair(0x01);
    let payload = b"block-proposal".to_vec();

    let msg_s0 = GossipMessage::sign(
        &kp,
        GossipTopic::shard_blocks(0),
        "mainnet",
        payload.clone(),
    )
    .unwrap();
    let msg_s1 =
        GossipMessage::sign(&kp, GossipTopic::shard_blocks(1), "mainnet", payload).unwrap();

    // Each verifies on its own shard
    assert!(msg_s0.verify().unwrap(), "Shard 0 message must verify");
    assert!(msg_s1.verify().unwrap(), "Shard 1 message must verify");

    // Swap topics: cross-shard injection must fail
    let mut swapped = msg_s0.clone();
    swapped.topic = GossipTopic::shard_blocks(1);
    assert!(
        !swapped.verify().unwrap(),
        "Shard 0 message with shard 1 topic must fail — no cross-shard injection"
    );

    println!("✓ Cross-shard gossip injection prevented by topic-bound context strings");
}

//     // ══════════════════════════════════════════════════════════════════════════
//     // GROUP 7: Overhead documentation
//     // ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_network_identity_and_message_overhead() {
    let kp = make_keypair(0x01);
    let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
    let msg = GossipMessage::sign(
        &kp,
        GossipTopic::shard_blocks(0),
        "mainnet",
        b"block-hash".to_vec(),
    )
    .unwrap();

    println!("=== Huxplex L0 Network Identity Overhead ===");
    println!(
        "PeerId:             {:3} B  (SHAKE-256(ML-DSA-44 PK)[0..32])",
        pid.id.len()
    );
    println!(
        "ML-DSA-44 PK:      {:4} B  (gossip message sender identity)",
        kp.public_key().bytes.len()
    );
    println!(
        "ML-DSA-44 Sig:     {:4} B  (per gossip message)",
        msg.sig.bytes.len()
    );
    println!(
        "Topic string:       {:3} B  ('{}')",
        msg.topic.as_str().len(),
        msg.topic.as_str()
    );
    println!(
        "Context string:     {:3} B  ('{}')",
        gossip_context("mainnet", &msg.topic).len(),
        std::str::from_utf8(&gossip_context("mainnet", &msg.topic)).unwrap()
    );
    println!("Ed25519 sig equiv:   64 B");
    println!(
        "PQ gossip overhead: {}x per message signature",
        msg.sig.bytes.len() / 64
    );

    assert_eq!(pid.id.len(), 32);
    assert_eq!(msg.sig.bytes.len(), 2420);
    assert_eq!(kp.public_key().bytes.len(), 1312);
}
