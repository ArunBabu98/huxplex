use crate::{
    crypto::{
        error::CryptoResult,
        publickey::PublicKey,
        signature::{Keypair, Signature},
    },
    network::topic::{GossipTopic, gossip_context},
};

#[derive(Clone, Debug)]
pub struct GossipMessage {
    pub topic: GossipTopic,
    pub network: String, // "mainnet" | "testnet"
    pub payload: Vec<u8>,
    pub sig: Signature,
    pub from: PublicKey, // ML-DSA-44 public key of sender
}

impl GossipMessage {
    pub fn sign(
        keypair: &Keypair,
        topic: GossipTopic,
        network: &str,
        payload: Vec<u8>,
    ) -> CryptoResult<Self> {
        let ctx = gossip_context(network, &topic);
        let sig = keypair.sign(&payload, Some(&ctx))?;
        Ok(GossipMessage {
            topic,
            network: network.to_string(),
            payload,
            sig,
            from: keypair.public_key().clone(),
        })
    }

    pub fn verify(&self) -> CryptoResult<bool> {
        let ctx = gossip_context(&self.network, &self.topic);
        self.from.verify(&self.payload, &self.sig, Some(&ctx))
    }
}

/// A Kademlia DHT entry — authenticated with ML-DSA-44 per spec.
#[derive(Clone, Debug)]
pub struct DhtEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub sig: Signature,
    pub signer_pk: PublicKey,
}

impl DhtEntry {
    pub fn sign(keypair: &Keypair, key: Vec<u8>, value: Vec<u8>) -> CryptoResult<Self> {
        let mut payload = Vec::with_capacity(key.len() + value.len());
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&value);
        let ctx = b"huxplex-mainnet:dht:entry:v1";
        let sig = keypair.sign(&payload, Some(ctx))?;
        Ok(DhtEntry {
            key,
            value,
            sig,
            signer_pk: keypair.public_key().clone(),
        })
    }

    pub fn verify(&self) -> CryptoResult<bool> {
        let mut payload = Vec::with_capacity(self.key.len() + self.value.len());
        payload.extend_from_slice(&self.key);
        payload.extend_from_slice(&self.value);
        let ctx = b"huxplex-mainnet:dht:entry:v1";
        self.signer_pk.verify(&payload, &self.sig, Some(ctx))
    }
}
