use hux_crypto::context::{self, Purpose};

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
