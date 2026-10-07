//! Gate **G2a** — canonical wire encoding of `GossipMessage` and `DhtEntry`
//! ([ADR-0022](../../../docs/adr/0022-g2-split-wire-and-consensus-encoding.md)).
//!
//! | Test | Property |
//! |---|---|
//! | **G2-T1** | `decode(encode(x)) == x` **and** `encode(decode(b)) == b` |
//! | **G2-T2** | hand-crafted alternate encodings are refused at decode |
//! | **G2-T4** | 10⁶ random byte strings never panic and never decode to a value that re-encodes differently |
//! | **G1-T6** | the `(role, version)` descriptor is on the wire and inside the signature |
//! | freeze | committed golden encodings still decode, verify and re-encode byte for byte |

use hux_crypto::{
    context::Network,
    error::CryptoError,
    signature::{Keypair, Signature},
    signaturescheme::SignatureSchemeId,
    suite::{AlgoSuite, SigRole, SuiteError, SuiteVersion},
};
use hux_network::{
    message::{DhtEntry, GossipMessage, MAX_ENVELOPE_LEN},
    topic::{GossipTopic, gossip_context},
};
use hux_types::codec::{Codec, CodecError};

fn kp(seed: u8) -> Keypair {
    Keypair::generate(SignatureSchemeId::Dilithium2, [seed; 32]).unwrap()
}

fn gossip(seed: u8, topic: GossipTopic, network: &str, payload: &[u8]) -> GossipMessage {
    GossipMessage::sign(&kp(seed), topic, network, payload.to_vec()).unwrap()
}

fn dht(seed: u8, key: &[u8], value: &[u8], network: &str) -> DhtEntry {
    DhtEntry::sign(&kp(seed), key.to_vec(), value.to_vec(), network).unwrap()
}

fn samples() -> (Vec<GossipMessage>, Vec<DhtEntry>) {
    let g = vec![
        gossip(1, GossipTopic::intents(), "mainnet", b""),
        gossip(2, GossipTopic::shard_blocks(0), "testnet", b"block"),
        gossip(
            3,
            GossipTopic::shard_mempool(u16::MAX),
            "mainnet",
            &[0xAB; 300],
        ),
        gossip(
            4,
            GossipTopic::shard_blocks(128),
            "testnet",
            &vec![0x5A; 64 * 1024],
        ),
    ];
    let d = vec![
        dht(5, b"", b"", "mainnet"),
        dht(6, &[0x11; 32], b"/ip4/10.0.0.1/udp/9000/quic-v1", "testnet"),
        dht(7, b"abc", b"XY", "mainnet"),
        dht(8, b"ab", b"cXY", "mainnet"),
    ];
    (g, d)
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

// ─── G2-T1 · round trip and re-encode stability ──────────────────────────────────────────────

#[test]
fn g2_t1_round_trip_and_re_encode_stability() {
    let (g, d) = samples();
    for msg in g {
        let bytes = msg.encode();
        let back = GossipMessage::decode(&bytes).unwrap();
        assert_eq!(back, msg, "decode(encode(x)) != x");
        assert_eq!(back.encode(), bytes, "encode(decode(b)) != b");
        assert!(
            back.verify().unwrap(),
            "a decoded message must still verify"
        );
    }
    for entry in d {
        let bytes = entry.encode();
        let back = DhtEntry::decode(&bytes).unwrap();
        assert_eq!(back, entry);
        assert_eq!(back.encode(), bytes);
        assert!(back.verify().unwrap());
    }
}

#[test]
fn g2_t1_the_dht_boundary_forgery_is_closed_by_the_codec() {
    // ("abc","XY") and ("ab","cXY") must have different signed preimages — the 2026-09-23
    // forgery, now prevented by the codec's length prefixes rather than hand-written framing.
    let honest = dht(9, b"abc", b"XY", "mainnet");
    let mut forged = honest.clone();
    forged.key = b"ab".to_vec();
    forged.value = b"cXY".to_vec();
    assert_ne!(honest.signing_preimage(), forged.signing_preimage());
    assert!(!forged.verify().unwrap());
}

// ─── G2-T2 · non-canonical encodings are rejected ────────────────────────────────────────────

fn valid_gossip_bytes() -> Vec<u8> {
    gossip(10, GossipTopic::shard_blocks(3), "mainnet", b"payload").encode()
}

#[test]
fn g2_t2_trailing_bytes_are_rejected() {
    let mut bytes = valid_gossip_bytes();
    bytes.push(0x00);
    assert_eq!(GossipMessage::decode(&bytes), Err(CodecError::NonCanonical));
}

#[test]
fn g2_t2_an_overlong_varint_is_rejected() {
    // The role is the first byte: 0x00 (Transaction). [0x80, 0x00] is the same value spelt in two
    // bytes — a valid varint, and the textbook second encoding of one value.
    let bytes = valid_gossip_bytes();
    assert_eq!(bytes[0], 0x00);
    let mut overlong = vec![0x80, 0x00];
    overlong.extend_from_slice(&bytes[1..]);
    assert!(
        GossipMessage::decode(&overlong).is_err(),
        "overlong role varint accepted"
    );

    // The same for a length prefix: the payload length 7 spelt as [0x87, 0x00].
    let topic_len = bytes[3] as usize;
    let payload_len_at = 4 + topic_len;
    assert_eq!(bytes[payload_len_at], 7);
    let mut overlong = bytes[..payload_len_at].to_vec();
    overlong.extend_from_slice(&[0x87, 0x00]);
    overlong.extend_from_slice(&bytes[payload_len_at + 1..]);
    assert!(
        GossipMessage::decode(&overlong).is_err(),
        "overlong length accepted"
    );
}

#[test]
fn g2_t2_unregistered_identifiers_are_rejected() {
    let bytes = valid_gossip_bytes();
    let malformed = |at: usize, value: u8| {
        let mut b = bytes.clone();
        b[at] = value;
        matches!(GossipMessage::decode(&b), Err(CodecError::Malformed(_)))
    };
    assert!(malformed(0, 5), "unknown role accepted");
    assert!(malformed(1, 0), "suite version 0 accepted");
    assert!(malformed(1, 2), "unknown suite version accepted");
    assert!(malformed(2, 0), "network code 0 accepted");
    assert!(malformed(2, 3), "unknown network accepted");
}

#[test]
fn g2_t2_a_key_of_the_wrong_length_for_its_scheme_is_rejected() {
    // Re-declare the ML-DSA key as SLH-DSA: a registered scheme, but 1,312 bytes is not its key
    // length. Refused at decode, before anything tries to verify with it.
    let bytes = valid_gossip_bytes();
    let topic_len = bytes[3] as usize;
    let scheme_at = 4 + topic_len + 1 + 7;
    assert_eq!(
        bytes[scheme_at],
        SignatureSchemeId::Dilithium2.as_u16() as u8
    );
    let mut b = bytes.clone();
    b[scheme_at] = SignatureSchemeId::SlhDsa128s.as_u16() as u8;
    assert!(matches!(
        GossipMessage::decode(&b),
        Err(CodecError::Malformed(_))
    ));
}

#[test]
fn g2_t2_a_non_canonical_topic_is_rejected() {
    // shard/007 is shard 7 spelt differently. As a topic string it would be a second replay
    // domain for one shard, so it does not decode.
    let msg = gossip(11, GossipTopic::shard_blocks(7), "mainnet", b"x");
    let bytes = msg.encode();
    let canonical = b"huxplex/shard/7/blocks";
    let padded = b"huxplex/shard/007/blocks";
    let at = bytes
        .windows(canonical.len())
        .position(|w| w == canonical)
        .unwrap();
    let mut b = bytes[..at - 1].to_vec();
    b.push(padded.len() as u8);
    b.extend_from_slice(padded);
    b.extend_from_slice(&bytes[at + canonical.len()..]);
    assert!(matches!(
        GossipMessage::decode(&b),
        Err(CodecError::Malformed(_))
    ));

    for bad in [
        "huxplex/shard/007/blocks",
        "huxplex/shard/+7/blocks",
        "huxplex/shard/65536/blocks",
        "huxplex/shard//blocks",
        "huxplex/shard/1/other",
        "huxplex/Intents",
    ] {
        assert_eq!(GossipTopic::parse(bad), None, "{bad} parsed");
    }
    assert_eq!(
        GossipTopic::parse("huxplex/shard/0/mempool"),
        Some(GossipTopic::shard_mempool(0))
    );
}

#[test]
fn g2_t2_truncation_is_rejected_at_every_length() {
    let bytes = dht(12, b"k", b"v", "testnet").encode();
    for len in 0..bytes.len() {
        assert!(
            DhtEntry::decode(&bytes[..len]).is_err(),
            "accepted a {len}-byte prefix"
        );
    }
}

#[test]
fn g2_t2_oversized_input_is_refused_by_length() {
    let bytes = vec![0u8; MAX_ENVELOPE_LEN + 1];
    assert_eq!(
        GossipMessage::decode(&bytes),
        Err(CodecError::TooLarge {
            max: MAX_ENVELOPE_LEN,
            actual: MAX_ENVELOPE_LEN + 1
        })
    );
}

// ─── G2-T4 · random and mutated inputs ───────────────────────────────────────────────────────

/// xorshift64* — deterministic, so a failure reproduces from the printed iteration.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The G2-T4 property for one input: no panic (the harness would abort), and anything that
/// decodes re-encodes to exactly the input — so no two distinct byte strings share a value.
fn check<T: Codec>(bytes: &[u8]) -> bool {
    match T::decode(bytes) {
        Ok(v) => {
            assert_eq!(
                v.encode(),
                bytes,
                "decoded to a value that re-encodes differently"
            );
            true
        }
        Err(_) => false,
    }
}

#[test]
fn g2_t4_a_million_random_byte_strings() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut buf = Vec::with_capacity(256);
    for _ in 0..1_000_000 {
        buf.clear();
        let len = rng.below(256);
        // Bias the first bytes towards valid descriptor and network codes, so the decoder is
        // driven past the first field rather than rejecting almost everything at byte 0.
        for i in 0..len {
            let byte = match i {
                0 => rng.below(6) as u8,
                1 => rng.below(3) as u8,
                2 => rng.below(4) as u8,
                _ => rng.next() as u8,
            };
            buf.push(byte);
        }
        check::<GossipMessage>(&buf);
        check::<DhtEntry>(&buf);
    }
}

#[test]
fn g2_t4_mutations_of_valid_encodings() {
    let (g, d) = samples();
    let seeds: Vec<(Vec<u8>, bool)> = g
        .iter()
        .take(3)
        .map(|m| (m.encode(), true))
        .chain(d.iter().map(|e| (e.encode(), false)))
        .collect();

    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..20_000 {
        let (base, is_gossip) = &seeds[rng.below(seeds.len())];
        let mut b = base.clone();
        match rng.below(4) {
            0 => {
                let at = rng.below(b.len());
                b[at] ^= 1 << rng.below(8);
            }
            1 => b.truncate(rng.below(b.len())),
            2 => {
                let at = rng.below(b.len() + 1);
                b.insert(at, rng.next() as u8);
            }
            _ => {
                let at = rng.below(b.len());
                b.remove(at);
            }
        }
        if *is_gossip {
            check::<GossipMessage>(&b);
        } else {
            check::<DhtEntry>(&b);
        }
    }
}

// ─── G1-T6 · the descriptor is on the wire and inside the signature ──────────────────────────

#[test]
fn g1_t6_a_relabelled_role_is_refused_as_role_confusion() {
    let (g, d) = samples();
    for &role in SigRole::ALL {
        if role == SigRole::Transaction {
            continue;
        }
        let mut msg = g[1].clone();
        msg.suite = AlgoSuite::new(role, SuiteVersion::V1);
        assert!(
            matches!(
                msg.verify(),
                Err(CryptoError::Suite(SuiteError::RoleMismatch { expected: SigRole::Transaction, actual })) if actual == role
            ),
            "gossip relabelled to {role:?} was not refused as role confusion"
        );

        let mut entry = d[1].clone();
        entry.suite = AlgoSuite::new(role, SuiteVersion::V1);
        assert!(matches!(
            entry.verify(),
            Err(CryptoError::Suite(SuiteError::RoleMismatch { .. }))
        ));
    }
}

#[test]
fn g1_t6_the_descriptor_is_inside_the_signed_preimage() {
    // The structural check above is a verifier rule. This is the cryptographic binding beneath
    // it: the role is part of the signed bytes, so a relabelled envelope's preimage differs and
    // the original signature does not verify over it — even for a verifier that skipped the role
    // check.
    let (g, _) = samples();
    let msg = &g[1];
    let ctx = gossip_context(msg.network.as_str(), &msg.topic);
    for &role in SigRole::ALL {
        let mut relabelled = msg.clone();
        relabelled.suite = AlgoSuite::new(role, SuiteVersion::V1);
        let same = role == SigRole::Transaction;
        assert_eq!(
            relabelled.signing_preimage() == msg.signing_preimage(),
            same
        );
        assert_eq!(
            msg.from
                .verify(&relabelled.signing_preimage(), &msg.sig, Some(&ctx))
                .unwrap(),
            same,
            "the signature verified over a preimage relabelled to {role:?}"
        );
    }
}

#[test]
fn g1_t6_the_descriptor_must_resolve_to_the_signers_scheme() {
    // An SLH-DSA key cannot sign gossip: the Transaction role resolves to ML-DSA-44. Refused at
    // signing, and an envelope assembled by hand with one is refused at verification.
    let slh = Keypair::generate_from_seed(SignatureSchemeId::SlhDsa128s, &[3u8; 48]).unwrap();
    assert!(matches!(
        GossipMessage::sign(&slh, GossipTopic::intents(), "mainnet", b"x".to_vec()),
        Err(CryptoError::SchemeMismatch { .. })
    ));

    let (g, _) = samples();
    let mut msg = g[0].clone();
    msg.from = slh.public_key().clone();
    msg.sig = Signature {
        scheme: SignatureSchemeId::SlhDsa128s,
        bytes: slh.sign(b"x", None).unwrap().bytes,
    };
    assert!(matches!(
        msg.verify(),
        Err(CryptoError::SchemeMismatch { .. })
    ));
}

#[test]
fn unregistered_networks_fail_closed_at_signing() {
    assert!(matches!(
        GossipMessage::sign(&kp(1), GossipTopic::intents(), "devnet", vec![]),
        Err(CryptoError::UnknownNetwork(n)) if n == "devnet"
    ));
    assert!(matches!(
        DhtEntry::sign(&kp(1), vec![], vec![], "Mainnet"),
        Err(CryptoError::UnknownNetwork(_))
    ));
}

// ─── The freeze — golden encodings ───────────────────────────────────────────────────────────

#[test]
fn wire_v1_golden_gossip_message() {
    // G2a freezes the wire format. These bytes were produced at the freeze; if this test fails,
    // the wire format changed, and that is a network-breaking change, not a refactor.
    let bytes = unhex(include_str!("wire/gossip_message_v1.hex"));
    let msg = GossipMessage::decode(&bytes).unwrap();
    assert_eq!(
        msg.suite,
        AlgoSuite::new(SigRole::Transaction, SuiteVersion::V1)
    );
    assert_eq!(msg.network, Network::Testnet);
    assert_eq!(msg.topic, GossipTopic::shard_mempool(3));
    assert_eq!(msg.payload, b"huxplex wire v1");
    assert!(msg.verify().unwrap());
    assert_eq!(msg.encode(), bytes);

    // The descriptor leads the encoding (data-model spec §1 rule 7): role 0, version 1, then the
    // network code.
    assert_eq!(&bytes[..3], &[0x00, 0x01, Network::Testnet.code()]);
}

#[test]
fn wire_v1_golden_dht_entry() {
    let bytes = unhex(include_str!("wire/dht_entry_v1.hex"));
    let entry = DhtEntry::decode(&bytes).unwrap();
    assert_eq!(entry.network, Network::Mainnet);
    assert_eq!(entry.value, b"/ip4/127.0.0.1/udp/9000/quic-v1");
    assert_eq!(
        entry.key,
        hux_network::peer::PeerId::from_ml_dsa_pk(entry.signer_pk.clone()).id,
        "the golden record is keyed by its publisher's PeerId"
    );
    assert!(entry.verify().unwrap());
    assert_eq!(entry.encode(), bytes);
}
