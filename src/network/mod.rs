pub mod error;
pub mod message;
pub mod peer;
pub mod topic;

#[cfg(test)]
mod network_tests {
    use crate::{
        crypto::{
            kem::{EK_SIZE, kem768_keygen},
            signature::Keypair,
            signaturescheme::SignatureSchemeId,
            *,
        },
        network::{
            message::{DhtEntry, GossipMessage},
            peer::PeerId,
            topic::{GossipTopic, gossip_context},
        },
    };
    // ── Shared fixtures ───────────────────────────────────────────────────────
    fn make_keypair(seed: u8) -> Keypair {
        Keypair::generate(SignatureSchemeId::Dilithium2, [seed; 32]).unwrap()
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 1: PeerId derivation
    // peer_id = SHAKE-256(ml_dsa44_public_key_bytes)[0..32]
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_peer_id_is_32_bytes() {
        let kp = make_keypair(0x01);
        let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        assert_eq!(
            pid.id.len(),
            32,
            "PeerId must be exactly 32 bytes (SHAKE-256 output)"
        );
    }

    #[test]
    fn test_peer_id_is_deterministic_from_same_key() {
        let kp = make_keypair(0x01);
        let pid1 = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        let pid2 = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        assert_eq!(
            pid1, pid2,
            "Same ML-DSA-44 key must always produce the same PeerId"
        );
    }

    #[test]
    fn test_peer_id_is_non_trivial() {
        let kp = make_keypair(0x01);
        let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        assert_ne!(pid.id, [0u8; 32], "PeerId must never be all-zero");
        assert_ne!(pid.id, [0xFFu8; 32], "PeerId must never be all-0xFF");
    }

    #[test]
    fn test_different_ml_dsa_keys_produce_different_peer_ids() {
        let kp1 = make_keypair(0x01);
        let kp2 = make_keypair(0x02);
        let pid1 = PeerId::from_ml_dsa_pk(kp1.public_key().clone());
        let pid2 = PeerId::from_ml_dsa_pk(kp2.public_key().clone());
        assert_ne!(
            pid1, pid2,
            "Different ML-DSA-44 keys must produce different PeerIds"
        );
    }

    #[test]
    fn test_five_validator_peer_ids_are_all_distinct() {
        let pids: Vec<PeerId> = (1u8..=5)
            .map(|i| PeerId::from_ml_dsa_pk(make_keypair(i).public_key().clone()))
            .collect();

        for i in 0..pids.len() {
            for j in (i + 1)..pids.len() {
                assert_ne!(
                    pids[i], pids[j],
                    "Validator PeerIds {i} and {j} must be distinct"
                );
            }
        }
        println!("✓ 5 validator PeerIds — all distinct");
    }

    #[test]
    fn test_peer_id_does_not_equal_ml_kem_key_fingerprint() {
        // PeerId is derived from ML-DSA-44 PK (identity/auth key).
        // ML-KEM-768 EK is the session KEM key (different role).
        // They must not produce the same 32-byte fingerprint.
        let kp = make_keypair(0x01);
        let (kem_ek, _) = kem768_keygen([0x01u8; 64]);
        let dsa_pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());

        // ML-KEM EK is 1184 bytes, ML-DSA PK is 1312 bytes — sizes differ entirely
        assert_ne!(
            kp.public_key().bytes.len(),
            EK_SIZE,
            "ML-DSA-44 PK size must differ from ML-KEM-768 EK size"
        );
        // The peer ID bytes must not accidentally equal the first 32 bytes of the KEM EK
        assert_ne!(
            dsa_pid.id,
            kem_ek[..32],
            "PeerId must not collide with the ML-KEM EK prefix"
        );
    }

    #[test]
    fn test_peer_id_hex_display_is_lowercase_64_chars() {
        let kp = make_keypair(0x42);
        let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        let hex = pid.to_hex();
        assert_eq!(hex.len(), 64, "PeerId hex must be 64 characters (32 bytes)");
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "PeerId hex must only contain hex digits"
        );
        assert!(
            hex.chars().all(|c| !c.is_uppercase()),
            "PeerId hex must be lowercase"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 2: GossipSub topic strings
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
        let msg = GossipMessage::sign(&kp, GossipTopic::shard_blocks(3), "mainnet", large_payload)
            .unwrap();
        assert!(msg.verify().unwrap(), "64 KB gossip payload must verify");
    }

    //     // ══════════════════════════════════════════════════════════════════════════
    //     // GROUP 5: DHT entry authentication
    //     // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dht_entry_sign_and_verify_roundtrip() {
        let kp = make_keypair(0x10);
        let peer_id = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        let value = b"127.0.0.1:30333".to_vec();

        let entry = DhtEntry::sign(&kp, peer_id.id.to_vec(), value).unwrap();
        assert!(entry.verify().unwrap(), "Valid DHT entry must verify");
    }

    #[test]
    fn test_dht_entry_tampered_value_fails_verification() {
        let kp = make_keypair(0x10);
        let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        let mut entry = DhtEntry::sign(&kp, pid.id.to_vec(), b"127.0.0.1:30333".to_vec()).unwrap();

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
        let mut entry = DhtEntry::sign(&kp, pid.id.to_vec(), b"127.0.0.1:30333".to_vec()).unwrap();

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
        let mut entry = DhtEntry::sign(&kp1, pid.id.to_vec(), b"127.0.0.1:30333".to_vec()).unwrap();

        // Route poisoning: attacker swaps in their own public key
        entry.signer_pk = kp2.public_key().clone();
        assert!(
            !entry.verify().unwrap(),
            "Wrong signer public key must fail DHT entry verification"
        );
    }

    #[test]
    fn test_dht_entry_key_matches_peer_id_of_signing_key() {
        // Best practice: the DHT key should be the peer's own PeerId.
        // This test verifies the binding is consistent.
        let kp = make_keypair(0x10);
        let pid = PeerId::from_ml_dsa_pk(kp.public_key().clone());
        let entry = DhtEntry::sign(&kp, pid.id.to_vec(), b"127.0.0.1:30333".to_vec()).unwrap();

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

    //     #[test]
    //     fn test_full_node_identity_pipeline() {
    //         // Simulates a new node joining the network:
    //         // 1. Generates ML-DSA-44 identity keypair
    //         // 2. Derives PeerId from it
    //         // 3. Publishes a DHT entry announcing its address
    //         // 4. Signs and broadcasts a gossip message on a shard topic

    //         let kp = make_keypair(0xAA);
    //         let pid = PeerId::from_ml_dsa_pk(kp.public_key());

    //         // Step 3: DHT announcement
    //         let dht = DhtEntry::sign(&kp, pid.0.to_vec(), b"10.0.0.1:30333".to_vec()).unwrap();
    //         assert!(dht.verify().unwrap(), "Node DHT announcement must be valid");

    //         // Step 4: Gossip broadcast
    //         let msg = GossipMessage::sign(
    //             &kp,
    //             GossipTopic::shard_blocks(0),
    //             "mainnet",
    //             b"genesis-block-hash".to_vec(),
    //         )
    //         .unwrap();
    //         assert!(msg.verify().unwrap(), "Node gossip broadcast must be valid");

    //         // Peer ID consistency: the same ML-DSA-44 key drives both
    //         let pid_from_dht_signer = PeerId::from_ml_dsa_pk(&dht.signer_pk);
    //         assert_eq!(
    //             pid, pid_from_dht_signer,
    //             "DHT signer PeerId must match node PeerId"
    //         );

    //         let pid_from_msg_sender = PeerId::from_ml_dsa_pk(&msg.from);
    //         assert_eq!(
    //             pid, pid_from_msg_sender,
    //             "Gossip sender PeerId must match node PeerId"
    //         );

    //         println!("✓ Full node identity pipeline: keygen → PeerId → DHT → GossipMessage");
    //     }

    //     #[test]
    //     fn test_ten_validators_each_with_unique_peer_id_and_valid_dht_entries() {
    //         // Simulates 10 validators in a Q-BFT set.
    //         // Each must have a unique PeerId and valid authenticated DHT presence.
    //         let validators: Vec<_> = (1u8..=10)
    //             .map(|i| {
    //                 let kp = make_keypair(i);
    //                 let pid = PeerId::from_ml_dsa_pk(kp.public_key());
    //                 let dht = DhtEntry::sign(
    //                     &kp,
    //                     pid.0.to_vec(),
    //                     format!("192.168.1.{}:30333", i).into_bytes(),
    //                 )
    //                 .unwrap();
    //                 (pid, dht)
    //             })
    //             .collect();

    //         // All PeerIds distinct
    //         for i in 0..validators.len() {
    //             for j in (i + 1)..validators.len() {
    //                 assert_ne!(
    //                     validators[i].0, validators[j].0,
    //                     "Validators {i} and {j} must have distinct PeerIds"
    //                 );
    //             }
    //         }

    //         // All DHT entries valid
    //         for (i, (_, dht)) in validators.iter().enumerate() {
    //             assert!(
    //                 dht.verify().unwrap(),
    //                 "Validator {i} DHT entry must be valid"
    //             );
    //         }

    //         println!("✓ 10-validator set: all PeerIds unique, all DHT entries authenticated");
    //     }

    //     #[test]
    //     fn test_cross_shard_gossip_messages_use_different_contexts() {
    //         // A validator proposing on shard 0 must use a different context than shard 1.
    //         // Tests that no shard can accidentally validate another shard's messages.
    //         let kp = make_keypair(0x01);
    //         let payload = b"block-proposal".to_vec();

    //         let msg_s0 = GossipMessage::sign(
    //             &kp,
    //             GossipTopic::shard_blocks(0),
    //             "mainnet",
    //             payload.clone(),
    //         )
    //         .unwrap();
    //         let msg_s1 =
    //             GossipMessage::sign(&kp, GossipTopic::shard_blocks(1), "mainnet", payload).unwrap();

    //         // Each verifies on its own shard
    //         assert!(msg_s0.verify().unwrap(), "Shard 0 message must verify");
    //         assert!(msg_s1.verify().unwrap(), "Shard 1 message must verify");

    //         // Swap topics: cross-shard injection must fail
    //         let mut swapped = msg_s0.clone();
    //         swapped.topic = GossipTopic::shard_blocks(1);
    //         assert!(
    //             !swapped.verify().unwrap(),
    //             "Shard 0 message with shard 1 topic must fail — no cross-shard injection"
    //         );

    //         println!("✓ Cross-shard gossip injection prevented by topic-bound context strings");
    //     }

    //     // ══════════════════════════════════════════════════════════════════════════
    //     // GROUP 7: Overhead documentation
    //     // ══════════════════════════════════════════════════════════════════════════

    //     #[test]
    //     fn test_network_identity_and_message_overhead() {
    //         let kp = make_keypair(0x01);
    //         let pid = PeerId::from_ml_dsa_pk(kp.public_key());
    //         let msg = GossipMessage::sign(
    //             &kp,
    //             GossipTopic::shard_blocks(0),
    //             "mainnet",
    //             b"block-hash".to_vec(),
    //         )
    //         .unwrap();

    //         println!("=== Huxplex L0 Network Identity Overhead ===");
    //         println!(
    //             "PeerId:             {:3} B  (SHAKE-256(ML-DSA-44 PK)[0..32])",
    //             pid.0.len()
    //         );
    //         println!(
    //             "ML-DSA-44 PK:      {:4} B  (gossip message sender identity)",
    //             kp.public_key().bytes.len()
    //         );
    //         println!(
    //             "ML-DSA-44 Sig:     {:4} B  (per gossip message)",
    //             msg.sig.bytes.len()
    //         );
    //         println!(
    //             "Topic string:       {:3} B  ('{}')",
    //             msg.topic.as_str().len(),
    //             msg.topic.as_str()
    //         );
    //         println!(
    //             "Context string:     {:3} B  ('{}')",
    //             gossip_context("mainnet", &msg.topic).len(),
    //             std::str::from_utf8(&gossip_context("mainnet", &msg.topic)).unwrap()
    //         );
    //         println!("Ed25519 sig equiv:   64 B");
    //         println!(
    //             "PQ gossip overhead: {}x per message signature",
    //             msg.sig.bytes.len() / 64
    //         );

    //         assert_eq!(pid.0.len(), 32);
    //         assert_eq!(msg.sig.bytes.len(), 2420);
    //         assert_eq!(kp.public_key().bytes.len(), 1312);
    //     }
}
