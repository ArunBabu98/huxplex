//! The signed wire envelopes — `GossipMessage` and `DhtEntry` — under the canonical codec
//! (gate **G2a**, [ADR-0022](../../../docs/adr/0022-g2-split-wire-and-consensus-encoding.md)).
//!
//! # Wire layout — frozen at G2a
//!
//! Every envelope is `body ‖ signature`, and the signature is made over the canonical encoding of
//! the **body** — every field but the signature — under the envelope's context string:
//!
//! ```text
//! GossipMessage = suite ‖ network ‖ topic ‖ payload ‖ from      ‖ sig
//! DhtEntry      = suite ‖ network ‖ key   ‖ value   ‖ signer_pk ‖ sig
//!                 └──────────────── body (signed) ──────────────┘
//! ```
//!
//! **The descriptor comes first and is signed.** ADR-0011 rule 3′ requires the full
//! `(role, version)` descriptor on every signed object, and putting it inside the signed body is
//! what binds a signature to its role (**G1-T6**): relabel the role and the preimage changes, so
//! the signature no longer verifies. It is also why G2a could not start before the G1 registry —
//! a wire format frozen without the descriptor would have made adding it a state migration.
//!
//! **Every variable-length field is length-prefixed by the codec**, which retires the hand-framed
//! `u64_be(len) ‖ …` encoding `DhtEntry` used after the 2026-09-23 re-splitting forgery (ADR-0011
//! rule 5′: superseded by `Codec` at G2a).

use hux_crypto::{
    context::{GOSSIP_ROLE, Network, Purpose},
    error::{CryptoError, CryptoResult},
    publickey::PublicKey,
    signature::{Keypair, Signature},
    suite::{AlgoSuite, SigRole, SuiteError, SuiteVersion},
};
use hux_types::{
    codec::{Codec, CodecError, from_canonical, to_canonical},
    wire::{WireNetwork, WirePublicKey, WireSignature, WireSuite},
};
use serde::{Deserialize, Serialize};

use crate::topic::{GossipTopic, dht_entry_context, gossip_context};

/// Upper bound on an encoded envelope, checked before any decoding work.
///
/// A codec-level sanity bound, not the policy limit: per-topic payload maxima are governance
/// parameters (wire spec §5) and the transport enforces its own frame size at G5. This exists so
/// an oversized input is refused by length, not by exhausting memory first.
pub const MAX_ENVELOPE_LEN: usize = 4 * 1024 * 1024;

fn network(name: &str) -> CryptoResult<Network> {
    Network::parse(name).ok_or_else(|| CryptoError::UnknownNetwork(name.to_string()))
}

/// The descriptor a new envelope is signed under: its context's role, at the current suite.
fn suite_for(role: SigRole, keypair: &Keypair) -> CryptoResult<AlgoSuite> {
    let suite = AlgoSuite::new(role, SuiteVersion::V1);
    let scheme = suite.signature_scheme()?;
    if keypair.public_key().scheme != scheme {
        return Err(CryptoError::SchemeMismatch {
            expected: scheme,
            actual: keypair.public_key().scheme,
        });
    }
    Ok(suite)
}

/// Checks a received descriptor against the role its context belongs to and the key it claims.
///
/// Both checks run **before** any signature work and report as themselves: a role relabel is a
/// `RoleMismatch`, not a failed signature (G1-T6), and a descriptor that resolves to a different
/// scheme than the signer's key is a `SchemeMismatch`.
fn check_descriptor(
    suite: AlgoSuite,
    expected_role: SigRole,
    signer: &PublicKey,
) -> CryptoResult<()> {
    if suite.role != expected_role {
        return Err(SuiteError::RoleMismatch {
            expected: expected_role,
            actual: suite.role,
        }
        .into());
    }
    let scheme = suite.signature_scheme()?;
    if signer.scheme != scheme {
        return Err(CryptoError::SchemeMismatch {
            expected: scheme,
            actual: signer.scheme,
        });
    }
    Ok(())
}

// ─── GossipMessage ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipMessage {
    /// `(role, version)` — always `Transaction` for gossip (crypto spec §5). Signed.
    pub suite: AlgoSuite,
    pub topic: GossipTopic,
    pub network: Network,
    pub payload: Vec<u8>,
    pub sig: Signature,
    /// The sender's public key; its scheme must be the one `suite` resolves to.
    pub from: PublicKey,
}

#[derive(Serialize, Deserialize)]
struct GossipBody {
    suite: WireSuite,
    network: WireNetwork,
    topic: GossipTopic,
    payload: Vec<u8>,
    from: WirePublicKey,
}

#[derive(Serialize, Deserialize)]
struct GossipWire {
    body: GossipBody,
    sig: WireSignature,
}

impl GossipMessage {
    pub fn sign(
        keypair: &Keypair,
        topic: GossipTopic,
        network: &str,
        payload: Vec<u8>,
    ) -> CryptoResult<Self> {
        let suite = suite_for(GOSSIP_ROLE, keypair)?;
        let network = self::network(network)?;
        let from = keypair.public_key().clone();
        let body = Self::body(suite, network, &topic, &payload, &from);
        let sig = keypair.sign(
            &to_canonical(&body),
            Some(&gossip_context(network.as_str(), &topic)),
        )?;
        Ok(GossipMessage {
            suite,
            topic,
            network,
            payload,
            sig,
            from,
        })
    }

    /// Verifies the descriptor, then the signature over the canonical body.
    ///
    /// `Ok(false)` is a signature that does not verify — tampering, replay across topic, network
    /// or key. `Err` is a structurally wrong envelope: a role or scheme the descriptor does not
    /// permit. Callers must not collapse the two (peer scoring treats them differently at G5).
    pub fn verify(&self) -> CryptoResult<bool> {
        check_descriptor(self.suite, GOSSIP_ROLE, &self.from)?;
        let ctx = gossip_context(self.network.as_str(), &self.topic);
        self.from
            .verify(&self.signing_preimage(), &self.sig, Some(&ctx))
    }

    /// The bytes the signature covers: the canonical encoding of every field but `sig`.
    pub fn signing_preimage(&self) -> Vec<u8> {
        to_canonical(&Self::body(
            self.suite,
            self.network,
            &self.topic,
            &self.payload,
            &self.from,
        ))
    }

    fn body(
        suite: AlgoSuite,
        network: Network,
        topic: &GossipTopic,
        payload: &[u8],
        from: &PublicKey,
    ) -> GossipBody {
        GossipBody {
            suite: WireSuite(suite),
            network: WireNetwork(network),
            topic: topic.clone(),
            payload: payload.to_vec(),
            from: WirePublicKey(from.clone()),
        }
    }
}

impl Codec for GossipMessage {
    fn encode(&self) -> Vec<u8> {
        to_canonical(&GossipWire {
            body: Self::body(
                self.suite,
                self.network,
                &self.topic,
                &self.payload,
                &self.from,
            ),
            sig: WireSignature(self.sig.clone()),
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let GossipWire { body, sig } = from_canonical(bytes, MAX_ENVELOPE_LEN)?;
        Ok(GossipMessage {
            suite: body.suite.0,
            topic: body.topic,
            network: body.network.0,
            payload: body.payload,
            sig: sig.0,
            from: body.from.0,
        })
    }
}

// ─── DhtEntry ────────────────────────────────────────────────────────────────────────────────

/// A Kademlia DHT record — the key SHOULD be the publisher's `PeerId` (wire spec §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhtEntry {
    /// `(role, version)` — `Transaction`, the role of `dht:entry` (crypto spec §5). Signed.
    pub suite: AlgoSuite,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub network: Network,
    pub sig: Signature,
    pub signer_pk: PublicKey,
}

#[derive(Serialize, Deserialize)]
struct DhtBody {
    suite: WireSuite,
    network: WireNetwork,
    key: Vec<u8>,
    value: Vec<u8>,
    signer_pk: WirePublicKey,
}

#[derive(Serialize, Deserialize)]
struct DhtWire {
    body: DhtBody,
    sig: WireSignature,
}

impl DhtEntry {
    pub fn sign(
        keypair: &Keypair,
        key: Vec<u8>,
        value: Vec<u8>,
        network: &str,
    ) -> CryptoResult<Self> {
        let suite = suite_for(Purpose::DhtEntry.role(), keypair)?;
        let network = self::network(network)?;
        let signer_pk = keypair.public_key().clone();
        let body = Self::body(suite, network, &key, &value, &signer_pk);
        let sig = keypair.sign(
            &to_canonical(&body),
            Some(&dht_entry_context(network.as_str())),
        )?;
        Ok(DhtEntry {
            suite,
            key,
            value,
            network,
            sig,
            signer_pk,
        })
    }

    /// As [`GossipMessage::verify`].
    pub fn verify(&self) -> CryptoResult<bool> {
        check_descriptor(self.suite, Purpose::DhtEntry.role(), &self.signer_pk)?;
        let ctx = dht_entry_context(self.network.as_str());
        self.signer_pk
            .verify(&self.signing_preimage(), &self.sig, Some(&ctx))
    }

    /// The bytes the signature covers: the canonical encoding of every field but `sig`.
    ///
    /// `key` and `value` are each length-prefixed by the codec, so `("abc","XY")` and
    /// `("ab","cXY")` encode differently — the property the 2026-09-23 forgery violated, now held
    /// by the codec rather than by hand-written framing.
    pub fn signing_preimage(&self) -> Vec<u8> {
        to_canonical(&Self::body(
            self.suite,
            self.network,
            &self.key,
            &self.value,
            &self.signer_pk,
        ))
    }

    fn body(
        suite: AlgoSuite,
        network: Network,
        key: &[u8],
        value: &[u8],
        signer_pk: &PublicKey,
    ) -> DhtBody {
        DhtBody {
            suite: WireSuite(suite),
            network: WireNetwork(network),
            key: key.to_vec(),
            value: value.to_vec(),
            signer_pk: WirePublicKey(signer_pk.clone()),
        }
    }
}

impl Codec for DhtEntry {
    fn encode(&self) -> Vec<u8> {
        to_canonical(&DhtWire {
            body: Self::body(
                self.suite,
                self.network,
                &self.key,
                &self.value,
                &self.signer_pk,
            ),
            sig: WireSignature(self.sig.clone()),
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let DhtWire { body, sig } = from_canonical(bytes, MAX_ENVELOPE_LEN)?;
        Ok(DhtEntry {
            suite: body.suite.0,
            key: body.key,
            value: body.value,
            network: body.network.0,
            sig: sig.0,
            signer_pk: body.signer_pk.0,
        })
    }
}
