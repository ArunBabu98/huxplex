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
pub fn gossip_context(network: &str, topic: &GossipTopic) -> Vec<u8> {
    format!("huxplex-{network}:gossip:{}:v1", topic.as_str()).into_bytes()
}
