use hux_crypto::{
    error::CryptoResult,
    publickey::PublicKey,
    signature::{Keypair, Signature},
};

use crate::topic::{GossipTopic, dht_entry_context, gossip_context};

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
    pub network: String, // "mainnet" | "testnet"
    pub sig: Signature,
    pub signer_pk: PublicKey,
}

impl DhtEntry {
    pub fn sign(
        keypair: &Keypair,
        key: Vec<u8>,
        value: Vec<u8>,
        network: &str,
    ) -> CryptoResult<Self> {
        let payload = Self::payload(&key, &value);
        let ctx = dht_entry_context(network);
        let sig = keypair.sign(&payload, Some(&ctx))?;
        Ok(DhtEntry {
            key,
            value,
            network: network.to_string(),
            sig,
            signer_pk: keypair.public_key().clone(),
        })
    }

    pub fn verify(&self) -> CryptoResult<bool> {
        let payload = Self::payload(&self.key, &self.value);
        let ctx = dht_entry_context(&self.network);
        self.signer_pk.verify(&payload, &self.sig, Some(&ctx))
    }

    /// Builds the signed payload with each field framed by its own length.
    ///
    /// ```text
    /// u64_be(key.len()) ‖ key ‖ u64_be(value.len()) ‖ value
    /// ```
    ///
    /// **Why framing, and not bare `key ‖ value`.** Concatenation alone does not encode where
    /// the key ends, so `("abc", "XY")` and `("ab", "cXY")` produce identical signed bytes. The
    /// DHT key decides routing and lookup, so an attacker who observes any signed record could
    /// re-split it and republish the publisher's signature under a *different* key — without
    /// holding a private key. [`DhtEntry::verify`] recomputes this payload from `self`, so it
    /// accepted the forgery.
    ///
    /// That directly contradicts G5-T5 (*"a record signed for one key cannot be republished
    /// under another"*), and it is the canonical-encoding failure G2-T2 exists to forbid: two
    /// distinct values must never share one encoding.
    ///
    /// Length-prefixing the key alone would disambiguate, since the value is then the
    /// remainder. Both fields are framed anyway, so the payload is self-describing and stays
    /// unambiguous if a field is ever appended.
    ///
    /// This is a deliberately local framing, not a general codec. Structured consensus objects
    /// get the canonical `Codec` at G2 (ADR-0011); this function is the grandfathered primitive
    /// encoding for a type that predates it, made correct in place.
    fn payload(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(16 + key.len() + value.len());
        payload.extend_from_slice(&(key.len() as u64).to_be_bytes());
        payload.extend_from_slice(key);
        payload.extend_from_slice(&(value.len() as u64).to_be_bytes());
        payload.extend_from_slice(value);
        payload
    }
}
