//! Canonical GossipSub topic strings and their derived context strings.
//!
//! Extracted from `lib.rs` at gate G0 (workspace migration, task W2). Integration tests reach
//! only the public API of `hux-network` and `hux-crypto`.
//!
//! See `docs/18-implementation-plan/00-workspace-migration.md`.

use hux_crypto::{signature::Keypair, signaturescheme::SignatureSchemeId};
use hux_network::{
    message::GossipMessage,
    topic::{GossipTopic, gossip_context},
};

fn make_keypair(seed: u8) -> Keypair {
    Keypair::generate(SignatureSchemeId::Dilithium2, [seed; 32]).unwrap()
}

// ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_shard_blocks_topic_format() {
    assert_eq!(
        GossipTopic::shard_blocks(0).as_str(),
        "huxplex/shard/0/blocks"
    );
    assert_eq!(
        GossipTopic::shard_blocks(1).as_str(),
        "huxplex/shard/1/blocks"
    );
    assert_eq!(
        GossipTopic::shard_blocks(15).as_str(),
        "huxplex/shard/15/blocks"
    );
    assert_eq!(
        GossipTopic::shard_blocks(255).as_str(),
        "huxplex/shard/255/blocks"
    );
}

#[test]
fn test_shard_mempool_topic_format() {
    assert_eq!(
        GossipTopic::shard_mempool(0).as_str(),
        "huxplex/shard/0/mempool"
    );
    assert_eq!(
        GossipTopic::shard_mempool(7).as_str(),
        "huxplex/shard/7/mempool"
    );
    assert_eq!(
        GossipTopic::shard_mempool(255).as_str(),
        "huxplex/shard/255/mempool"
    );
}

#[test]
fn test_intents_topic_format() {
    assert_eq!(GossipTopic::intents().as_str(), "huxplex/intents");
}

#[test]
fn test_blocks_and_mempool_topics_for_same_shard_are_distinct() {
    let blocks = GossipTopic::shard_blocks(0);
    let mempool = GossipTopic::shard_mempool(0);
    assert_ne!(
        blocks, mempool,
        "blocks and mempool topics for shard 0 must be distinct"
    );
}

#[test]
fn test_same_topic_type_different_shards_are_distinct() {
    let shard_0 = GossipTopic::shard_blocks(0);
    let shard_1 = GossipTopic::shard_blocks(1);
    assert_ne!(
        shard_0, shard_1,
        "shard 0 and shard 1 block topics must be distinct — no cross-shard gossip leakage"
    );
}

#[test]
fn test_intents_topic_distinct_from_all_shard_topics() {
    let intents = GossipTopic::intents();
    for shard_id in [0u16, 1, 7, 255] {
        assert_ne!(intents, GossipTopic::shard_blocks(shard_id));
        assert_ne!(intents, GossipTopic::shard_mempool(shard_id));
    }
    println!("✓ Intent gossip overlay is distinct from all shard topics");
}

#[test]
fn test_sixteen_shard_topics_all_unique() {
    // Simulates a 16-shard deployment — all topic strings must be unique.
    let mut topics = Vec::new();
    for shard in 0u16..16 {
        topics.push(GossipTopic::shard_blocks(shard));
        topics.push(GossipTopic::shard_mempool(shard));
    }
    topics.push(GossipTopic::intents());

    let mut seen = std::collections::HashSet::new();
    for t in &topics {
        assert!(
            seen.insert(t.as_str().to_string()),
            "Duplicate topic: {}",
            t.as_str()
        );
    }
    println!(
        "✓ All {} topics unique across 16-shard deployment",
        topics.len()
    );
}

//     // ══════════════════════════════════════════════════════════════════════════
//     // GROUP 3: Gossip context string derivation
//     // b"huxplex-{network}:gossip:{topic}:v1"
//     // ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_gossip_context_format_shard_blocks() {
    let topic = GossipTopic::shard_blocks(0);
    let ctx = gossip_context("mainnet", &topic);
    assert_eq!(ctx, b"huxplex-mainnet:gossip:huxplex/shard/0/blocks:v1");
}

#[test]
fn test_gossip_context_format_intents() {
    let ctx = gossip_context("mainnet", &GossipTopic::intents());
    assert_eq!(ctx, b"huxplex-mainnet:gossip:huxplex/intents:v1");
}

#[test]
fn test_gossip_context_mainnet_vs_testnet_differs() {
    let topic = GossipTopic::shard_blocks(0);
    let ctx_main = gossip_context("mainnet", &topic);
    let ctx_test = gossip_context("testnet", &topic);
    assert_ne!(
        ctx_main, ctx_test,
        "Mainnet and testnet gossip contexts must differ"
    );
}

#[test]
fn test_gossip_context_different_topics_differ() {
    let ctx_blocks = gossip_context("mainnet", &GossipTopic::shard_blocks(0));
    let ctx_mempool = gossip_context("mainnet", &GossipTopic::shard_mempool(0));
    let ctx_intents = gossip_context("mainnet", &GossipTopic::intents());
    assert_ne!(ctx_blocks, ctx_mempool);
    assert_ne!(ctx_blocks, ctx_intents);
    assert_ne!(ctx_mempool, ctx_intents);
}

#[test]
fn test_gossip_context_different_shard_ids_differ() {
    let ctx_0 = gossip_context("mainnet", &GossipTopic::shard_blocks(0));
    let ctx_1 = gossip_context("mainnet", &GossipTopic::shard_blocks(1));
    assert_ne!(
        ctx_0, ctx_1,
        "Context strings for different shards must differ"
    );
}

//     // ══════════════════════════════════════════════════════════════════════════
//     // GROUP 4: GossipMessage sign and verify roundtrip
//     // ══════════════════════════════════════════════════════════════════════════

#[test]
fn test_gossip_message_sign_and_verify_roundtrip() {
    let kp = make_keypair(0x01);
    let topic = GossipTopic::shard_blocks(0);
    let payload = b"block-hash:deadbeef".to_vec();

    let msg = GossipMessage::sign(&kp, topic, "mainnet", payload).unwrap();
    assert!(msg.verify().unwrap(), "Valid gossip message must verify");
}

#[test]
fn test_gossip_message_tampered_payload_fails_verification() {
    let kp = make_keypair(0x01);
    let topic = GossipTopic::shard_blocks(0);
    let mut msg =
        GossipMessage::sign(&kp, topic, "mainnet", b"block-hash:deadbeef".to_vec()).unwrap();

    // Tamper with one byte of the payload
    msg.payload[0] ^= 0xFF;
    assert!(
        !msg.verify().unwrap(),
        "Tampered payload must fail gossip message verification"
    );
}

#[test]
fn test_gossip_message_wrong_public_key_fails_verification() {
    let kp1 = make_keypair(0x01);
    let kp2 = make_keypair(0x02);
    let topic = GossipTopic::shard_blocks(0);

    let mut msg =
        GossipMessage::sign(&kp1, topic, "mainnet", b"block-hash:deadbeef".to_vec()).unwrap();

    // Swap in a different node's public key
    msg.from = kp2.public_key().clone();
    assert!(
        !msg.verify().unwrap(),
        "Wrong sender public key must fail gossip message verification"
    );
}

#[test]
fn test_gossip_message_wrong_network_context_fails_verification() {
    let kp = make_keypair(0x01);
    let topic = GossipTopic::shard_blocks(0);
    let mut msg =
        GossipMessage::sign(&kp, topic, "mainnet", b"block-hash:deadbeef".to_vec()).unwrap();

    // Switch to testnet after signing
    msg.network = "testnet".to_string();
    assert!(
        !msg.verify().unwrap(),
        "Mainnet gossip message must not verify on testnet context"
    );
}

#[test]
fn test_gossip_message_wrong_shard_topic_fails_verification() {
    // A message signed for shard 0 must not verify when the topic is changed to shard 1.
    // Prevents cross-shard gossip injection.
    let kp = make_keypair(0x01);
    let topic_shard0 = GossipTopic::shard_blocks(0);
    let mut msg =
        GossipMessage::sign(&kp, topic_shard0, "mainnet", b"shard-0-block".to_vec()).unwrap();

    msg.topic = GossipTopic::shard_blocks(1);
    assert!(
        !msg.verify().unwrap(),
        "Shard 0 gossip message must not verify with shard 1 topic context"
    );
}

#[test]
fn test_gossip_message_blocks_topic_sig_rejected_on_mempool_topic() {
    // A block gossip signature must not satisfy mempool context — different topic, same shard.
    let kp = make_keypair(0x01);
    let topic_blocks = GossipTopic::shard_blocks(0);
    let mut msg =
        GossipMessage::sign(&kp, topic_blocks, "mainnet", b"block-payload".to_vec()).unwrap();

    msg.topic = GossipTopic::shard_mempool(0);
    assert!(
        !msg.verify().unwrap(),
        "Blocks topic signature must not verify under mempool topic context"
    );
}

#[test]
fn test_intent_gossip_message_sign_and_verify() {
    let kp = make_keypair(0x05);
    let payload = b"intent:partial-tx:deadbeef".to_vec();
    let msg = GossipMessage::sign(&kp, GossipTopic::intents(), "mainnet", payload).unwrap();
    assert!(msg.verify().unwrap(), "Intent gossip message must verify");
}

#[test]
fn test_intent_sig_rejected_on_block_topic() {
    // A signature made for the intent overlay must not verify on a shard blocks topic.
    let kp = make_keypair(0x05);
    let mut msg = GossipMessage::sign(
        &kp,
        GossipTopic::intents(),
        "mainnet",
        b"intent-payload".to_vec(),
    )
    .unwrap();
    msg.topic = GossipTopic::shard_blocks(0);
    assert!(
        !msg.verify().unwrap(),
        "Intent gossip sig must not satisfy block topic context"
    );
}

#[test]
fn test_gossip_message_empty_payload_is_signable() {
    let kp = make_keypair(0x01);
    let msg = GossipMessage::sign(&kp, GossipTopic::intents(), "mainnet", vec![]).unwrap();
    assert!(
        msg.verify().unwrap(),
        "Empty payload gossip message must verify"
    );
}

#[test]
fn test_gossip_message_large_payload_is_signable() {
    let kp = make_keypair(0x01);
    let large_payload = vec![0xABu8; 64 * 1024]; // 64 KB block body
    let msg =
        GossipMessage::sign(&kp, GossipTopic::shard_blocks(3), "mainnet", large_payload).unwrap();
    assert!(msg.verify().unwrap(), "64 KB gossip payload must verify");
}

//     // ══════════════════════════════════════════════════════════════════════════
//     // GROUP 5: DHT entry authentication
