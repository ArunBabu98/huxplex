use hux_crypto::context::{self, Purpose};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// All canonical GossipSub topics per spec.
/// Block/Tx Propagation: huxplex/shard/{shard_id}/blocks
///                       huxplex/shard/{shard_id}/mempool
/// Intent overlay:       huxplex/intents
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GossipTopic(pub String);

impl GossipTopic {
    pub fn shard_blocks(shard_id: u16) -> Self {
        GossipTopic(format!("huxplex/shard/{shard_id}/blocks"))
    }

    pub fn shard_mempool(shard_id: u16) -> Self {
        GossipTopic(format!("huxplex/shard/{shard_id}/mempool"))
    }

    pub fn intents() -> Self {
        GossipTopic("huxplex/intents".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Accepts exactly the canonical topic strings — the three shapes above, with `shard_id` a
    /// `u16` in plain decimal (no sign, no leading zeros).
    ///
    /// Fails closed. Each topic string becomes part of a signature context, so a non-canonical
    /// spelling such as `huxplex/shard/007/blocks` would name a context outside the registry —
    /// one shard with two topic strings is one shard with two replay domains.
    pub fn parse(s: &str) -> Option<Self> {
        if s == "huxplex/intents" {
            return Some(Self::intents());
        }
        let rest = s.strip_prefix("huxplex/shard/")?;
        let (id, kind) = rest.split_once('/')?;
        let canonical = !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_digit())
            && (id == "0" || !id.starts_with('0'));
        if !canonical {
            return None;
        }
        let shard_id: u16 = id.parse().ok()?;
        match kind {
            "blocks" => Some(Self::shard_blocks(shard_id)),
            "mempool" => Some(Self::shard_mempool(shard_id)),
            _ => None,
        }
    }
}

/// On the wire a topic is its string; decoding goes through [`GossipTopic::parse`].
impl Serialize for GossipTopic {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for GossipTopic {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        GossipTopic::parse(&s).ok_or_else(|| D::Error::custom(format!("non-canonical topic {s:?}")))
    }
}

/// Derives the ML-DSA-44 context string for a gossip message on this topic.
/// Format: b"huxplex-{network}:gossip:{topic}:v1"
///
/// Built by `hux_crypto::context`, the spec §5 registry, so the string has one definition.
pub fn gossip_context(network: &str, topic: &GossipTopic) -> Vec<u8> {
    context::gossip_context(network, topic.as_str())
}

/// Derives the ML-DSA-44 context string for an authenticated Kademlia DHT entry.
/// Format: b"huxplex-{network}:dht:entry:v1"
///
/// Network-generalized per the cryptography spec §5 rule 2 — a `mainnet` DHT record must not
/// verify under `testnet` and vice versa.
pub fn dht_entry_context(network: &str) -> Vec<u8> {
    context::context_for(network, Purpose::DhtEntry)
}
